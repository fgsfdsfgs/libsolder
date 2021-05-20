#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <switch.h>
#include <string.h>
#include <malloc.h>
#include <elf.h>

#include "solder.h"
#include "util.h"
#include "exports.h"

enum dynmod_flags_internal {
  // states
  MOD_RELOCATED   = 1 << 17,
  MOD_MAPPED      = 1 << 18,
  MOD_INITIALIZED = 1 << 19,
  // additional flags
  MOD_OWN_SYMTAB  = 1 << 24,
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

  Elf64_Dyn *dynamic;
  Elf64_Sym *dynsym;
  size_t num_dynsym;

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
  // we're already all done
  .flags = MOD_MAPPED | MOD_RELOCATED | MOD_INITIALIZED,
};

static dynmod_t *so_load(const char *filename) {
  size_t so_size = 0;
  Elf64_Ehdr *ehdr = NULL;
  Elf64_Phdr *phdr = NULL;
  Elf64_Shdr *shdr = NULL;
  char *shstrtab = NULL;

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

  DEBUG_PRINTF("`%s`: total elf size is %lu\n", filename, so_size);

  ehdr = memalign(ALIGN_PAGE, so_size);
  if (!ehdr) {
    set_error("Could not allocate %lu bytes for `%s`", so_size, filename);
    fclose(fd);
    free(mod);
    return NULL;
  }

  fread(ehdr, so_size, 1, fd);
  fclose(fd);

  if (memcmp(ehdr, ELFMAG, SELFMAG) != 0) {
    set_error("`%s` is not a valid ELF file", filename);
    goto err_free_so;
  }

  phdr = (Elf64_Phdr *)((uintptr_t)ehdr + ehdr->e_phoff);
  shdr = (Elf64_Shdr *)((uintptr_t)ehdr + ehdr->e_shoff);
  shstrtab = (char *)((uintptr_t)ehdr + shdr[ehdr->e_shstrndx].sh_offset);

  // calculate total size of the LOAD segments
  // total size = size of last load segment + vaddr of last load segment
  for (size_t i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD && phdr[i].p_memsz) {
      const size_t this_size = phdr[i].p_vaddr + phdr[i].p_memsz;
      if (this_size > mod->load_size) mod->load_size = this_size;
      ++mod->num_segs;
    }
  }

  DEBUG_PRINTF("`%s`: total memory reserved %lu; %lu segs total\n", filename, mod->load_size, mod->num_segs);

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
  for (size_t i = 0, n = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD && phdr[i].p_memsz) {
      if (phdr[i].p_flags & PF_R) mod->segs[n].pflags |= Perm_R;
      if (phdr[i].p_flags & PF_W) mod->segs[n].pflags |= Perm_W;
      if (phdr[i].p_flags & PF_X) mod->segs[n].pflags |= Perm_X;
      mod->segs[n].size = ALIGN_MEM(phdr[i].p_memsz, ALIGN_PAGE);
      mod->segs[n].virtbase = (void *)((Elf64_Addr)mod->load_virtbase + phdr[i].p_vaddr);
      // create an aligned copy of the segment
      mod->segs[n].base = memalign(ALIGN_PAGE, mod->segs[n].size);
      if (!mod->segs[n].base) {
        set_error("Could not allocate `%lu` bytes for segment %lu\n", mod->segs[n].size, n);
        goto err_free_load;
      }
      // fill it in
      memcpy(mod->segs[n].base, (void *)((uintptr_t)ehdr + phdr[i].p_offset),
        phdr[i].p_filesz);
      phdr[i].p_vaddr = (Elf64_Addr)mod->segs[n].virtbase;
      ++n;
    } else if (phdr[i].p_type == PT_DYNAMIC) {
      // remember the dynamic seg
      mod->dynamic = (Elf64_Dyn *)((Elf64_Addr)mod->load_virtbase + phdr[i].p_vaddr);
    }
  }

  // base is the base of the first segment
  mod->load_base = mod->segs[0].base;

  if (!mod->dynamic) {
    set_error("`%s` doesn't have a DYNAMIC segment", filename);
    goto err_free_load;
  }

  // find special sections
  for (int i = 0; i < ehdr->e_shnum; i++) {
    const char *sh_name = shstrtab + shdr[i].sh_name;
    if (!strcmp(sh_name, ".dynsym")) {
      mod->dynsym = (Elf64_Sym *)((Elf64_Addr)mod->load_virtbase + shdr[i].sh_addr);
      mod->num_dynsym = shdr[i].sh_size / sizeof(Elf64_Sym);
    } else if (!strcmp(sh_name, ".dynstr")) {
      mod->dynstrtab = (char *)((Elf64_Addr)mod->load_virtbase + shdr[i].sh_addr);
    } else if (!strcmp(sh_name, ".hash")) {
      // optional: if there's no hashtab, linear lookup will be used
      mod->hashtab = (uint32_t *)((Elf64_Addr)mod->load_virtbase + shdr[i].sh_addr);
    } else if (!strcmp(sh_name, ".init_array")) {
      mod->init_array = (void *)((Elf64_Addr)mod->load_virtbase + shdr[i].sh_addr);
      mod->num_init = shdr[i].sh_size / sizeof(void *);
    } else if (!strcmp(sh_name, ".fini_array")) {
      mod->fini_array = (void *)((Elf64_Addr)mod->load_virtbase + shdr[i].sh_addr);
      mod->num_fini = shdr[i].sh_size / sizeof(void *);
    }
  }

  if (mod->dynsym == NULL || mod->dynstrtab == NULL) {
    set_error("No symbol information in `%s`", filename);
    goto err_free_load;
  }

  // map all the segs in right away
  Result rc = 0;
  Handle self = envGetOwnProcessHandle();
  for (size_t i = 0; i < mod->num_segs; ++i) {
    rc = svcMapProcessCodeMemory(self, (u64)mod->segs[i].virtbase, (u64)mod->segs[i].base, mod->segs[i].size);
    if (R_FAILED(rc)) {
      set_error("`%s`: svcMapProcessCodeMemory failed on seg %lu:\n%08x", mod->name, i, rc);
      goto err_free_unmap;
    }
    rc = svcSetProcessMemoryPermission(self, (u64)mod->segs[i].virtbase, mod->segs[i].size, mod->segs[i].pflags);
    if (R_FAILED(rc)) {
      set_error("`%s`: svcSetProcessMemoryPermission failed on seg %lu:\n%08x", mod->name, i, rc);
      goto err_free_unmap;
    }
  }

  mod->name = ustrdup(filename);
  mod->flags |= MOD_MAPPED;

  free(ehdr); // don't need this no more

  return mod;

err_free_unmap:
  for (size_t i = 0; i < mod->num_segs; ++i)
    svcUnmapProcessCodeMemory(self, (u64)mod->segs[i].virtbase, (u64)mod->segs[i].base, mod->segs[i].size);
err_free_load:
  virtmemLock();
  virtmemRemoveReservation(mod->load_memrv);
  virtmemUnlock();
  for (size_t i = 0; i < mod->num_segs; ++i)
    free(mod->segs[i].base);
err_free_so:
  free(mod->segs);
  free(ehdr);
  free(mod);

  return NULL;
}

static inline const Elf64_Sym *so_lookup_in_module(const dynmod_t *mod, const char *symname) {
  if (!mod || !mod->dynsym || !mod->dynstrtab)
    return NULL;
  // if hashtab is available, use that for lookup, otherwise do linear search
  if (mod->hashtab)
    return elf_hashtab_lookup(mod->dynstrtab, mod->dynsym, mod->hashtab, symname);
  // sym 0 is always UNDEF
  for (size_t i = 1; i < mod->num_dynsym; ++i) {
    if (!strcmp(symname, mod->dynstrtab + mod->dynsym[i].st_name))
      return mod->dynsym + i;
  }
  return NULL;
}

static inline void *so_lookup(const char *symname) {
  if (!symname || !*symname)
    return NULL;
  const dynmod_t *mod = &so_list;
  while (mod) {
    const Elf64_Sym *sym = so_lookup_in_module(mod, symname);
    if (sym && sym->st_shndx != SHN_UNDEF)
      return (void *)((uintptr_t)mod->load_virtbase + sym->st_value);
    mod = mod->next;
  }
  return NULL;
}

static inline int so_process_relocs(dynmod_t *mod, const Elf64_Rela *rels, const size_t num_rels) {
  for (size_t j = 0; j < num_rels; j++) {
    uintptr_t *ptr = (uintptr_t *)((uintptr_t)mod->load_virtbase + rels[j].r_offset);
    const uintptr_t symno = ELF64_R_SYM(rels[j].r_info);
    const int type = ELF64_R_TYPE(rels[j].r_info);
    uintptr_t symval = 0;
    uintptr_t symbase = (uintptr_t)mod->load_virtbase;

    if (symno) {
      // if the reloc refers to a symbol, get the symbol value in there
      const Elf64_Sym *sym = &mod->dynsym[symno];
      if (sym->st_shndx == SHN_UNDEF) {
        const char *symname = mod->dynstrtab + sym->st_name;
        symval = (uintptr_t)so_lookup(symname);
        symbase = 0; // symbol is somewhere else
        if (!symval) DEBUG_PRINTF("`%s`: resolution failed for `%s`\n", mod->name, symname);
      } else { 
        symval = sym->st_value;
      }
    }

    switch (type) {
      case R_AARCH64_RELATIVE:
        // sometimes the value of r_addend is also at *ptr
        *ptr = symbase + rels[j].r_addend;
        break;
      case R_AARCH64_ABS64:
      case R_AARCH64_GLOB_DAT:
      case R_AARCH64_JUMP_SLOT:
        *ptr = symval + rels[j].r_addend;
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
  Elf64_Rela *rela = NULL;
  Elf64_Rela *jmprel = NULL;
  uint32_t pltrel = 0;
  size_t relasz = 0;
  size_t pltrelsz = 0;

  // find RELA and JMPREL
  for (Elf64_Dyn *dyn = mod->dynamic; dyn->d_tag != DT_NULL; dyn++) {
    switch (dyn->d_tag) {
      case DT_RELA:
        rela = (Elf64_Rela *)(mod->load_virtbase + dyn->d_un.d_ptr);
        break;
      case DT_RELASZ:
        relasz = dyn->d_un.d_val;
        break;
      case DT_JMPREL:
        // TODO: don't assume RELA
        jmprel = (Elf64_Rela *)(mod->load_virtbase + dyn->d_un.d_ptr);
        break;
      case DT_PLTREL:
        pltrel = dyn->d_un.d_val;
        break;
      case DT_PLTRELSZ:
        pltrelsz = dyn->d_un.d_val;
        break;
      default:
        break;
    }
  }

  if (rela && relasz) {
    DEBUG_PRINTF("`%s`: processing RELA@%p size %lu\n", mod->name, rela, relasz);
    if (so_process_relocs(mod, rela, relasz / sizeof(Elf64_Rela)))
      return -1;
  }

  if (jmprel && pltrelsz && pltrel) {
    // TODO: support DT_REL
    if (pltrel == DT_RELA) {
      DEBUG_PRINTF("`%s`: processing JMPREL@%p size %lu\n", mod->name, jmprel, pltrelsz);
      if (so_process_relocs(mod, jmprel, pltrelsz / sizeof(Elf64_Rela)))
        return -1;
    } else {
      DEBUG_PRINTF("`%s`: DT_JMPREL has unsupported type %08x\n", mod->name, pltrel);
    }
  }

  mod->flags |= MOD_RELOCATED;

  return 0;
}

static void so_initialize(dynmod_t *mod) {
  if (mod->init_array) {
    for (size_t i = 0; i < mod->num_init; ++i)
      if (mod->init_array[i])
        mod->init_array[i]();
  }
}

static void so_finalize(dynmod_t *mod) {
  if (mod->fini_array) {
    for (size_t i = 0; i < mod->num_fini; ++i)
      if (mod->fini_array[i])
        mod->fini_array[i]();
    mod->fini_array = NULL;
    mod->num_fini = 0;
  }
}

static int so_unload(dynmod_t *mod) {
  if (mod->load_base == NULL)
    return -1;

  DEBUG_PRINTF("`%s`: unloading\n", mod->name);

  // execute destructors, if any
  so_finalize(mod);

  DEBUG_PRINTF("`%s`: unmapping\n", mod->name);

  // unmap and free all segs
  Handle self = envGetOwnProcessHandle();
  Result rc;
  for (size_t i = 0; i < mod->num_segs; ++i) {
    // restore permissions if needed (maybe not needed at all)
    if (mod->segs[i].pflags != Perm_Rw) {
      rc = svcSetProcessMemoryPermission(self, (u64)mod->segs[i].virtbase, mod->segs[i].size, Perm_Rw);
      if (R_FAILED(rc)) DEBUG_PRINTF("* svcSetProcessMemoryPermission(seg %lu): error %08x\n", i, rc);
    }
    rc = svcUnmapProcessCodeMemory(self, (u64)mod->segs[i].virtbase, (u64)mod->segs[i].base, mod->segs[i].size);
    if (R_FAILED(rc)) DEBUG_PRINTF("* svcUnmapProcessCodeMemory(seg %lu): error %08x\n", i, rc);
    free(mod->segs[i].base);
    mod->segs[i].base = NULL;
  }

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

  DEBUG_PRINTF("`%s`: unloaded\n", mod->name);

  // free everything else
  free(mod->segs);
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

static int so_relocate_and_init(dynmod_t *mod) {
  if (so_relocate(mod))
    return -1;
  so_initialize(mod);
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

  // relocate and init it right away if not lazy
  if (!(flags & SOLDER_LAZY)) {
    if (so_relocate_and_init(mod)) {
      so_unload(mod);
      return NULL;
    }
  }

  mod->flags |= flags;
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
    DEBUG_PRINTF("`%s`: refcount is 0, unloading\n", mod->name);
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

  if (!(mod->flags & MOD_RELOCATED)) {
    // module isn't ready yet; try to finalize it
    if (so_relocate_and_init(mod)) {
      so_unload(mod);
      return NULL;
    }
  }

  // module has no exports
  if (!mod->dynsym || mod->num_dynsym <= 1) {
    set_error("`%s`: no exports available", mod->name);
    return NULL;
  }

  const Elf64_Sym *sym = so_lookup_in_module(mod, symname);
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
  // find data-looking segment
  for (size_t i = 0; i < mod->num_segs; ++i)
    if (mod->segs[i].pflags == Perm_R)
      return mod->segs[i].virtbase;

  return NULL;
}

void *solder_get_text_addr(void *handle) {
  if (!handle) {
    set_error("get_text_addr(): NULL handle");
    return NULL;
  }

  dynmod_t *mod = handle;
  // find text-looking segment
  for (size_t i = 0; i < mod->num_segs; ++i)
    if (mod->segs[i].pflags == Perm_Rx)
      return mod->segs[i].virtbase;

  return NULL;
}

int solder_hook_function(void *__restrict handle, const char *__restrict symname, void *dstaddr) {
  if (!handle) {
    set_error("hook_function(): NULL handle");
    return -1;
  }

  dynmod_t *mod = handle;
  if (mod->flags & MOD_MAPPED) {
    set_error("`%s`: Already remapped as R/X", mod->name);
    return -2;
  }

  uint32_t *srcaddr = solder_dlsym(handle, symname);
  if (!srcaddr) return -3;

  srcaddr[0] = 0x58000051u; // LDR X17, #0x8
  srcaddr[1] = 0xd61f0220u; // BR X17
  *(uint64_t *)(srcaddr + 2) = (uint64_t)dstaddr;

  return 0;
}
