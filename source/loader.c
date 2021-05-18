#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <switch.h>
#include <string.h>
#include <elf.h>

#include "solder.h"
#include "util.h"
#include "heap.h"
#include "exports.h"

enum dynmod_flags_internal {
  MOD_OWN_SYMTAB = 1 << 16,
};

typedef struct dynmod_seg {
  void *base;
  void *virtbase;
  size_t size;
  u64 pflags;
} dynmod_seg_t;

typedef struct dynmod {
  char *name;
  int flags;
  int refcount;

  void *load_base;
  void *load_virtbase;
  VirtmemReservation *load_memrv;
  size_t load_size;

  dynmod_seg_t *segs;
  size_t num_segs;

  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;
  Elf64_Dyn *dynamic;
  Elf64_Sym *dynsym;
  size_t num_dynsym;

  char *shstrtab;
  char *dynstrtab;
  uint32_t *hashtab;

  int (** init_array)(void);
  size_t num_init;

  int (** fini_array)(void);
  size_t num_fini;

  struct dynmod *next;
  struct dynmod *prev;
} dynmod_t;

// the main module is the head and is never unloaded
extern int _start;
static dynmod_t so_list = {
  "$main",
  .load_virtbase = (void *)&_start,
};

static inline Elf64_Shdr *so_find_section(dynmod_t *mod, const char *secname) {
  if (!mod || !mod->shstrtab || !mod->shdr || !mod->ehdr)
    return NULL;
  for (size_t i = 0; i < mod->ehdr->e_shnum; i++) {
    if (!strcmp(mod->shstrtab + mod->shdr[i].sh_name, secname))
      return mod->shdr + i;
  }
  return NULL;
}

static dynmod_t *so_load(const char *filename) {
  size_t so_size = 0;

  dynmod_t *mod = calloc(1, sizeof(dynmod_t));
  if (!mod) {
    set_error("Could not allocate dynmod header");
    return NULL;
  }

  FILE *fd = fopen(filename, "rb");
  if (fd == NULL) {
    set_error("Could not open `%s`", filename);
    free(mod);
    return NULL;
  }

  fseek(fd, 0, SEEK_END);
  so_size = ftell(fd);
  fseek(fd, 0, SEEK_SET);

  mod->ehdr = malloc(so_size);
  if (!mod->ehdr) {
    set_error("Could not allocate %lu bytes for `%s`", so_size, filename);
    fclose(fd);
    free(mod);
    return NULL;
  }

  fread(mod->ehdr, so_size, 1, fd);
  fclose(fd);

  if (memcmp(mod->ehdr, ELFMAG, SELFMAG) != 0) {
    set_error("`%s` is not a valid ELF file", filename);
    goto err_free_so;
  }

  mod->phdr = (Elf64_Phdr *)((uintptr_t)mod->ehdr + mod->ehdr->e_phoff);
  mod->shdr = (Elf64_Shdr *)((uintptr_t)mod->ehdr + mod->ehdr->e_shoff);
  mod->shstrtab = (char *)((uintptr_t)mod->ehdr + mod->shdr[mod->ehdr->e_shstrndx].sh_offset);

  // calculate total size of the LOAD segments
  // total size = size of last load segment + vaddr of last load segment
  for (size_t i = 0; i < mod->ehdr->e_phnum; i++) {
    if (mod->phdr[i].p_type == PT_LOAD && mod->phdr[i].p_memsz) {
      const size_t this_size = mod->phdr[i].p_vaddr + ALIGN_MEM(mod->phdr[i].p_memsz, mod->phdr[i].p_align);
      if (this_size > mod->load_size) mod->load_size = this_size;
      ++mod->num_segs;
    }
  }
  // align total size to page size
  mod->load_size = ALIGN_MEM(mod->load_size, ALIGN_PAGE);

  // allocate space for all load segments (align to page size)
  // TODO: find out a way to allocate memory that doesn't fuck with the heap
  mod->load_base = so_heap_alloc(mod->load_size);
  if (!mod->load_base) {
    set_error("Could not allocate %lu bytes while loading `%s`", filename);
    goto err_free_so;
  }
  memset(mod->load_base, 0, mod->load_size);

  // reserve virtual memory space for the entire LOAD zone while we're fucking with the ELF
  virtmemLock();
  mod->load_virtbase = virtmemFindCodeMemory(mod->load_size, ALIGN_PAGE);
  mod->load_memrv = virtmemAddReservation(mod->load_virtbase, mod->load_size);
  virtmemUnlock();

  // collect segments
  mod->segs = calloc(mod->num_segs, sizeof(*mod->segs));
  if (!mod->segs) {
    set_error("Could not allocate space for `%s`'s segment table", filename);
    goto err_free_load;
  }
  for (size_t i = 0, n = 0; i < mod->ehdr->e_phnum; i++) {
    if (mod->phdr[i].p_type == PT_LOAD && mod->phdr[i].p_memsz) {
      if (mod->phdr[i].p_flags & PF_R) mod->segs[n].pflags |= Perm_R;
      if (mod->phdr[i].p_flags & PF_W) mod->segs[n].pflags |= Perm_W;
      if (mod->phdr[i].p_flags & PF_X) mod->segs[n].pflags |= Perm_X;
      mod->segs[n].size = mod->phdr[i].p_memsz;
      mod->segs[n].base = (void *)((Elf64_Addr)mod->load_base + mod->phdr[i].p_vaddr);
      mod->segs[n].virtbase = (void *)((Elf64_Addr)mod->load_virtbase + mod->phdr[i].p_vaddr);
      mod->phdr[i].p_vaddr = (Elf64_Addr)mod->segs[n].virtbase;
      memcpy(mod->segs[n].base, (void *)((uintptr_t)mod->ehdr + mod->phdr[i].p_offset),
        mod->phdr[i].p_filesz);
      ++n;
    } else if (mod->phdr[i].p_type == PT_DYNAMIC) {
      // remember the dynamic seg
      mod->dynamic = (Elf64_Dyn *)((Elf64_Addr)mod->load_base + mod->phdr[i].p_vaddr);
    }
  }

  if (!mod->dynamic) {
    set_error("`%s` doesn't have a DYNAMIC segment", filename);
    goto err_free_load;
  }

  // find special sections
  for (int i = 0; i < mod->ehdr->e_shnum; i++) {
    const char *sh_name = mod->shstrtab + mod->shdr[i].sh_name;
    if (!strcmp(sh_name, ".dynsym")) {
      mod->dynsym = (Elf64_Sym *)((Elf64_Addr)mod->load_base + mod->shdr[i].sh_addr);
      mod->num_dynsym = mod->shdr[i].sh_size / sizeof(Elf64_Sym);
    } else if (!strcmp(sh_name, ".dynstr")) {
      mod->dynstrtab = (char *)((Elf64_Addr)mod->load_base + mod->shdr[i].sh_addr);
    } else if (!strcmp(sh_name, ".hash")) {
      // optional: if there's no hashtab, linear lookup will be used
      mod->hashtab = (uint32_t *)((Elf64_Addr)mod->load_base + mod->shdr[i].sh_addr);
    } else if (!strcmp(sh_name, ".init_array")) {
      mod->init_array = (void *)((Elf64_Addr)mod->load_virtbase + mod->shdr[i].sh_addr);
      mod->num_init = mod->shdr[i].sh_size / sizeof(void *);
    } else if (!strcmp(sh_name, ".fini_array")) {
      mod->fini_array = (void *)((Elf64_Addr)mod->load_virtbase + mod->shdr[i].sh_addr);
      mod->num_fini = mod->shdr[i].sh_size / sizeof(void *);
    }
  }

  if (mod->dynsym == NULL || mod->dynstrtab == NULL) {
    set_error("No symbol information in `%s`", filename);
    goto err_free_load;
  }

  mod->name = ustrdup(filename);

  return mod;

err_free_load:
  virtmemLock();
  virtmemRemoveReservation(mod->load_memrv);
  virtmemUnlock();
  so_heap_free(mod->load_base);
err_free_so:
  free(mod->segs);
  free(mod->ehdr);
  free(mod);

  return NULL;
}

static inline int so_process_relocs(dynmod_t *mod, const Elf64_Rela *rels, const size_t num_rels) {
  for (size_t j = 0; j < num_rels; j++) {
    uintptr_t *ptr = (uintptr_t *)((uintptr_t)mod->load_base + rels[j].r_offset);
    Elf64_Sym *sym = &mod->dynsym[ELF64_R_SYM(rels[j].r_info)];
    const int type = ELF64_R_TYPE(rels[j].r_info);
    switch (type) {
      case R_AARCH64_ABS64:
        // FIXME: = or += ?
        *ptr = (uintptr_t)mod->load_virtbase + sym->st_value + rels[j].r_addend;
        break;
      case R_AARCH64_RELATIVE:
        // sometimes the value of r_addend is also at *ptr
        *ptr = (uintptr_t)mod->load_virtbase + rels[j].r_addend;
        break;
      case R_AARCH64_GLOB_DAT:
      case R_AARCH64_JUMP_SLOT:
        if (sym->st_shndx != SHN_UNDEF)
          *ptr = (uintptr_t)mod->load_virtbase + sym->st_value + rels[j].r_addend;
        break;
      case R_AARCH64_NONE:
        break; // sorry nothing
      default:
        set_error("`%s`: Unknown relocation type: %x", mod->name, type);
        return -1;
    }
  }
  return 0;
}

static int so_relocate(dynmod_t *mod) {
  for (size_t i = 0; i < mod->ehdr->e_shnum; i++) {
    const char *sh_name = mod->shstrtab + mod->shdr[i].sh_name;
    if (!strcmp(sh_name, ".rela.dyn") || !strcmp(sh_name, ".rela.plt")) {
      const Elf64_Rela *rels = (Elf64_Rela *)((uintptr_t)mod->load_base + mod->shdr[i].sh_addr);
      const size_t num_rels = mod->shdr[i].sh_size / sizeof(Elf64_Rela);
      if (so_process_relocs(mod, rels, num_rels))
        return -1;
    }
  }
  return 0;
}

static inline const Elf64_Sym *so_lookup_symbol(const dynmod_t *mod, const char *symname) {
  if (!mod || !mod->dynsym || !mod->dynstrtab)
    return NULL;
  // if hashtab is available, use that for lookup, otherwise do linear search
  if (mod->hashtab)
    return elf_hashtab_lookup(mod->dynstrtab, mod->dynsym, mod->hashtab, symname);
  // sym 0 is always UNDEF
  for (size_t i = 1; i < mod->num_dynsym; ++i) {
    if (mod->dynsym[i].st_shndx != SHN_UNDEF && !strcmp(symname, mod->dynstrtab + mod->dynsym[i].st_name))
      return mod->dynsym + i;
  }
  return NULL;
}

static inline void *so_lookup(const char *symname) {
  if (!symname || !*symname)
    return NULL;
  const dynmod_t *mod = &so_list;
  while (mod) {
    const Elf64_Sym *sym = so_lookup_symbol(mod, symname);
    if (sym) return (void *)((uintptr_t)mod->load_virtbase + sym->st_value);
    mod = mod->next;
  }
  return NULL;
}

static inline int so_resolve_relocs(dynmod_t *mod, const Elf64_Rela *rels, const size_t num_rels, const int taint) {
  for (size_t j = 0; j < num_rels; j++) {
    uintptr_t *ptr = (uintptr_t *)((uintptr_t)mod->load_base + rels[j].r_offset);
    const Elf64_Sym *sym = &mod->dynsym[ELF64_R_SYM(rels[j].r_info)];
    // skip shit that's already defined
    if (sym->st_shndx != SHN_UNDEF) continue;
    const int type = ELF64_R_TYPE(rels[j].r_info);
    const char *name;
    void *othersym;
    switch (type) {
      case R_AARCH64_ABS64:
      case R_AARCH64_GLOB_DAT:
      case R_AARCH64_JUMP_SLOT:
        name = mod->dynstrtab + sym->st_name;
        othersym = so_lookup(name);
        if (othersym)
          *ptr = (uintptr_t)othersym + rels[j].r_addend;
        else if (taint) // make it crash in a predictable way when debugging
          *ptr = (type == R_AARCH64_ABS64) ? 0 : rels[j].r_offset;
        break;
      default:
        break;
    }
  }
  return 0;
}

static int so_resolve(dynmod_t *mod, const int taint_missing) {
  for (size_t i = 0; i < mod->ehdr->e_shnum; i++) {
    const char *sh_name = mod->shstrtab + mod->shdr[i].sh_name;
    if (!strcmp(sh_name, ".rela.dyn") || !strcmp(sh_name, ".rela.plt")) {
      Elf64_Rela *rela = (Elf64_Rela *)((uintptr_t)mod->load_base + mod->shdr[i].sh_addr);
      const size_t num_rela = mod->shdr[i].sh_size / sizeof(Elf64_Rela);
      if (so_resolve_relocs(mod, rela, num_rela, taint_missing))
        return -1;
    }
  }
  return 0;
}

static int so_unload(dynmod_t *mod) {
  if (mod->load_base == NULL)
    return -1;

  // execute destructors, if any
  if (mod->fini_array) {
    for (size_t i = 0; i < mod->num_fini; ++i)
      if (mod->fini_array[i])
        mod->fini_array[i]();
    mod->fini_array = NULL;
    mod->num_fini = 0;
  }

  if (mod->ehdr) {
    // someone forgot to free the temp data
    free(mod->ehdr);
  }

  // remap every non-RW segment as RW
  for (size_t i = 0; i < mod->num_segs; ++i) {
    if (mod->segs[i].pflags != Perm_Rw) {
      const u64 asize = ALIGN_MEM(mod->segs[i].size, ALIGN_PAGE);
      svcSetProcessMemoryPermission(envGetOwnProcessHandle(), (u64)mod->segs[i].virtbase, asize, Perm_Rw);
    }
  }

  // unmap everything
  svcUnmapProcessCodeMemory(envGetOwnProcessHandle(), (u64)mod->load_virtbase, (u64)mod->load_base, mod->load_size);

  // release virtual address range
  virtmemLock();
  virtmemRemoveReservation(mod->load_memrv);
  virtmemUnlock();

  // if we own the symtab, free it
  if (mod->flags & MOD_OWN_SYMTAB) {
    free(mod->dynsym);
    free(mod->dynstrtab);
    free(mod->hashtab);
  }

  so_heap_free(mod->load_base);
  mod->load_base = NULL;

  free(mod->name);
  free(mod);

  return 0;
}

static void so_link(dynmod_t *mod) {
  mod->next = so_list.next;
  mod->prev = &so_list;
  if (so_list.next)
    so_list.next->prev = mod;
  so_list.next = mod;
}

static void so_unlink(dynmod_t *mod) {
  if (mod->prev)
    mod->prev->next = mod->next;
  if (mod->next)
    mod->next->prev = mod->prev;
  mod->next = NULL;
  mod->prev = NULL;
}

static int so_map(dynmod_t *mod) {
  Result rc = 0;

  // map the entire thing as code memory
  rc = svcMapProcessCodeMemory(envGetOwnProcessHandle(), (u64)mod->load_virtbase, (u64)mod->load_base, mod->load_size);
  if (R_FAILED(rc)) {
    set_error("`%s`: svcMapProcessCodeMemory failed:\n%08x", mod->name, rc);
    return -1;
  }

  // set permissions for each seg
  for (size_t i = 0; i < mod->num_segs; ++i) {
    const u64 asize = ALIGN_MEM(mod->segs[i].size, ALIGN_PAGE); // align to page
    rc = svcSetProcessMemoryPermission(envGetOwnProcessHandle(), (u64)mod->segs[i].virtbase, asize, mod->segs[i].pflags);
    if (R_FAILED(rc)) {
      set_error("`%s`: could not map %u bytes of %x memory at %p:\n%08x",
        mod->name, asize, mod->segs[i].pflags, mod->segs[i].virtbase, rc);
      return -2;
    }
  }

  // after mapping all of the tables will be at virtmem, so change accordingly
  if (!(mod->flags & MOD_OWN_SYMTAB)) {
    if (mod->dynsym)
      mod->dynsym = (void *)(((uintptr_t)mod->dynsym - (uintptr_t)mod->load_base) + (uintptr_t)mod->load_virtbase);
    if (mod->hashtab)
      mod->hashtab = (void *)(((uintptr_t)mod->hashtab - (uintptr_t)mod->load_base) + (uintptr_t)mod->load_virtbase);
    if (mod->dynstrtab)
      mod->dynstrtab = (void *)(((uintptr_t)mod->dynstrtab - (uintptr_t)mod->load_base) + (uintptr_t)mod->load_virtbase);
  }
  if (mod->dynamic)
    mod->dynamic = (void *)(((uintptr_t)mod->dynamic - (uintptr_t)mod->load_base) + (uintptr_t)mod->load_virtbase);

  return 0;
}

static void so_flush_caches(dynmod_t *mod) {
  // crashes. apparently when using SetProcessMemoryPermission like this?
  // armDCacheFlush(mod->load_base, mod->load_size);
  // armICacheInvalidate(mod->load_virtbase, mod->load_size);
}

static int so_finalize(dynmod_t *mod) {
  // resolve all imports
  so_resolve(mod, 1);

  // try to map the module as executable
  if (so_map(mod)) return -1;

  // before running any loaded code flush the cpu cache
  so_flush_caches(mod);

  // execute constructors, if any
  if (mod->init_array) {
    for (size_t i = 0; i < mod->num_init; ++i)
      if (mod->init_array[i])
        mod->init_array[i]();
  }

  // remove the temp data (can't use headers after this)
  free(mod->ehdr);
  mod->ehdr = NULL;
  mod->phdr = NULL;
  mod->shdr = NULL;
  mod->shstrtab = NULL;

  // link it into the global module list
  so_link(mod);

  return 0;
}

void so_unload_all(void) {
  dynmod_t *mod = so_list.next;
  so_list.next = NULL;

  while (mod) {
    dynmod_t *next = mod->next;
    next->prev = NULL;
    so_unload(mod);
    mod = next;
  }

  // clear main module's exports if needed
  if (so_list.flags & MOD_OWN_SYMTAB) {
    free(so_list.dynsym); so_list.dynsym = NULL;
    free(so_list.dynstrtab); so_list.dynstrtab = NULL;
    free(so_list.hashtab); so_list.hashtab = NULL;
    so_list.flags &= ~MOD_OWN_SYMTAB;
  }
}

/* libsolder API begins */

void *solder_dlopen(const char *fname, int flags) {
  dynmod_t *mod = NULL;

  // see if the module is already loaded and just increase refcount if it is
  for (dynmod_t *p = so_list.next; p; p = p->next) {
    if (!strcmp(p->name, fname)) {
      mod = p;
      break;
    }
  }

  if (mod) {
    mod->refcount++;
    return mod;
  }

  // load the module
  mod = so_load(fname);
  if (!mod) return NULL;

  // relocate it
  if (so_relocate(mod)) {
    so_unload(mod);
    return NULL;
  }

  // if lazy loading isn't requested, resolve imports and load it right away
  if (!(flags & SOLDER_LAZY)) {
    if (so_finalize(mod)) {
      so_unload(mod);
      return NULL;
    }
  }

  mod->flags = flags;
  mod->refcount = 1;

  return mod;
}

int solder_dlclose(void *handle) {
  if (!handle) {
    set_error("dlclose(): NULL handle");
    return -1;
  }

  dynmod_t *mod = handle;
  // free the module when reference count reaches zero
  if (--mod->refcount <= 0) {
    so_unlink(mod);
    return so_unload(mod);
  }

  return 0;
}

void *solder_dlsym(void *__restrict handle, const char *__restrict symname) {
  if (!symname || symname[0] == '\0') {
    set_error("dlsym(): empty symname");
    return NULL;
  }

  if (!handle) {
    // NULL handle means main module
    handle = &so_list;
  }

  dynmod_t *mod = handle;

  if (mod->ehdr) {
    // module isn't ready yet; try to finalize it
    if (so_finalize(mod)) {
      so_unload(mod);
      return NULL;
    }
  }

  // module has no exports
  if (!mod->dynsym || mod->num_dynsym <= 1) {
    set_error("`%s`: no exports available", mod->name);
    return NULL;
  }

  const Elf64_Sym *sym = so_lookup_symbol(mod, symname);
  if (sym) return (void *)((uintptr_t)mod->load_virtbase + sym->st_value);

  set_error("`%s`: symbol `%s` not found", mod->name, symname);
  return NULL;
}

int solder_set_main_exports(const solder_export_t *exp, const int numexp) {
  Elf64_Sym *symtab = NULL;
  uint32_t *hashtab = NULL;
  char *strtab = NULL;

  if (exp != NULL) {
    // if we got a custom export table, turn it into a symtab and use it
    if (symtab_from_exports(exp, numexp, &symtab, &strtab, &hashtab) == 0)
      so_list.flags |= MOD_OWN_SYMTAB; // to free it later
  }

  // otherwise, or if the generator died for some reason, try to use the NRO's symtab
  // this requires the NRO to have been built with -rdynamic
  if (symtab == NULL) symtab_from_nro(&symtab, &strtab, &hashtab);

  // if it's still missing, bail
  if (symtab == NULL) return -1;

  so_list.num_dynsym = hashtab[1]; // nchain == number of symbols
  so_list.dynsym = symtab;
  so_list.hashtab = hashtab;
  so_list.dynstrtab = strtab;

  // we now have symbols for other libs to use, so we need to mark ourselves as GLOBAL
  so_list.flags |= SOLDER_GLOBAL;

  return 0;
}

void *solder_get_data_addr(void *handle) {
  if (!handle) {
    set_error("get_data_addr(): NULL handle");
    return NULL;
  }

  dynmod_t *mod = handle;
  if (mod->ehdr == NULL) {
    set_error("`%s`: Already mapped as R/X", mod->name);
    return NULL;
  }

  // find data-looking segment
  for (size_t i = 0; i < mod->num_segs; ++i)
    if (mod->segs[i].pflags == Perm_R)
      return mod->segs[i].base;

  return NULL;
}

void *solder_get_text_addr(void *handle) {
  if (!handle) {
    set_error("get_text_addr(): NULL handle");
    return NULL;
  }

  dynmod_t *mod = handle;
  if (mod->ehdr == NULL) {
    set_error("`%s`: Already mapped as R/X", mod->name);
    return NULL;
  }

  // find text-looking segment
  for (size_t i = 0; i < mod->num_segs; ++i)
    if (mod->segs[i].pflags == Perm_Rx)
      return mod->segs[i].base;

  return NULL;
}

int solder_hook_function(void *__restrict handle, const char *__restrict symname, void *dstaddr) {
  if (!handle) {
    set_error("hook_function(): NULL handle");
    return -1;
  }

  dynmod_t *mod = handle;
  if (mod->ehdr == NULL) {
    set_error("`%s`: Already mapped as R/X", mod->name);
    return -2;
  }

  uint32_t *srcaddr = solder_dlsym(handle, symname);
  if (!srcaddr) return -3;

  srcaddr[0] = 0x58000051u; // LDR X17, #0x8
  srcaddr[1] = 0xd61f0220u; // BR X17
  *(uint64_t *)(srcaddr + 2) = (uint64_t)dstaddr;

  return 0;
}
