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

typedef struct dynmod {
  char *name;
  int flags;
  int refcount;

  void *so_base;

  void *load_base;
  void *load_virtbase;
  size_t load_size;
  VirtmemReservation *load_memrv;

  void *text_base;
  void *text_virtbase;
  size_t text_size;

  void *data_base;
  void *data_virtbase;
  size_t data_size;

  Elf64_Ehdr *elf_hdr;
  Elf64_Phdr *prog_hdr;
  Elf64_Shdr *sec_hdr;
  Elf64_Sym *syms;
  int num_syms;

  char *shstrtab;
  char *dynstrtab;

  solder_export_t *exports;
  int num_exports;

  int (** fini_array)();
  int num_fini;

  struct dynmod *next;
  struct dynmod *prev;
} dynmod_t;

// the main module is the head and is never unloaded
static dynmod_t so_list = {
  "$main",
};

static dynmod_t *so_load(const char *filename) {
  size_t so_size = 0;
  int text_segno = -1;
  int data_segno = -1;
  int got_segno = -1;

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

  mod->so_base = malloc(so_size);
  if (!mod->so_base) {
    set_error("Could not allocate %lu bytes for `%s`", so_size, filename);
    fclose(fd);
    free(mod);
    return NULL;
  }

  fread(mod->so_base, so_size, 1, fd);
  fclose(fd);

  if (memcmp(mod->so_base, ELFMAG, SELFMAG) != 0) {
    set_error("`%s` is not a valid ELF file", filename);
    goto err_free_so;
  }

  mod->elf_hdr = (Elf64_Ehdr *)mod->so_base;
  mod->prog_hdr = (Elf64_Phdr *)((uintptr_t)mod->so_base + mod->elf_hdr->e_phoff);
  mod->sec_hdr = (Elf64_Shdr *)((uintptr_t)mod->so_base + mod->elf_hdr->e_shoff);
  mod->shstrtab = (char *)((uintptr_t)mod->so_base + mod->sec_hdr[mod->elf_hdr->e_shstrndx].sh_offset);

  // calculate total size of the LOAD segments
  size_t last_load_size = 0;
  uintptr_t last_load_vaddr = 0;
  for (int i = 0; i < mod->elf_hdr->e_phnum; i++) {
    if (mod->prog_hdr[i].p_type == PT_LOAD) {
      last_load_size = ALIGN_MEM(mod->prog_hdr[i].p_memsz, mod->prog_hdr[i].p_align);
      last_load_vaddr = mod->prog_hdr[i].p_vaddr;
      // take note of special segments
      if ((mod->prog_hdr[i].p_flags & PF_X) == PF_X)
        text_segno = i;
      else if ((mod->prog_hdr[i].p_flags & (PF_R | PF_W)) == PF_R)
        data_segno = i;
      else if (got_segno < 0)
        got_segno = i;
    }
  }
  // total size = size of last load segment + vaddr of last load segment
  mod->load_size = last_load_vaddr + last_load_size;
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

  // copy segments to where they belong

  // text
  mod->text_size = mod->prog_hdr[text_segno].p_memsz;
  mod->text_virtbase = (void *)(mod->prog_hdr[text_segno].p_vaddr + (Elf64_Addr)mod->load_virtbase);
  mod->text_base = (void *)(mod->prog_hdr[text_segno].p_vaddr + (Elf64_Addr)mod->load_base);
  mod->prog_hdr[text_segno].p_vaddr = (Elf64_Addr)mod->text_virtbase;
  memcpy(mod->text_base, (void *)((uintptr_t)mod->so_base + mod->prog_hdr[text_segno].p_offset),
    mod->prog_hdr[text_segno].p_filesz);

  // data
  mod->data_size = mod->prog_hdr[data_segno].p_memsz;
  mod->data_virtbase = (void *)(mod->prog_hdr[data_segno].p_vaddr + (Elf64_Addr)mod->load_virtbase);
  mod->data_base = (void *)(mod->prog_hdr[data_segno].p_vaddr + (Elf64_Addr)mod->load_base);
  mod->prog_hdr[data_segno].p_vaddr = (Elf64_Addr)mod->data_virtbase;
  memcpy(mod->data_base, (void *)((uintptr_t)mod->so_base + mod->prog_hdr[data_segno].p_offset),
    mod->prog_hdr[data_segno].p_filesz);

  // got
  void *got_virtbase = (void *)(mod->prog_hdr[got_segno].p_vaddr + (Elf64_Addr)mod->load_virtbase);
  void *got_base = (void *)(mod->prog_hdr[got_segno].p_vaddr + (Elf64_Addr)mod->load_base);
  mod->prog_hdr[got_segno].p_vaddr = (Elf64_Addr)got_virtbase;
  memcpy(got_base, (void *)((uintptr_t)mod->so_base + mod->prog_hdr[got_segno].p_offset),
    mod->prog_hdr[got_segno].p_filesz);

  mod->syms = NULL;
  mod->dynstrtab = NULL;

  for (int i = 0; i < mod->elf_hdr->e_shnum; i++) {
    const char *sh_name = mod->shstrtab + mod->sec_hdr[i].sh_name;
    if (strcmp(sh_name, ".dynsym") == 0) {
      mod->syms = (Elf64_Sym *)((uintptr_t)mod->text_base + mod->sec_hdr[i].sh_addr);
      mod->num_syms = mod->sec_hdr[i].sh_size / sizeof(Elf64_Sym);
    } else if (strcmp(sh_name, ".dynstr") == 0) {
      // make a duplicate of this for the exports table
      mod->dynstrtab = umemdup((const void *)((uintptr_t)mod->text_base + mod->sec_hdr[i].sh_addr), mod->sec_hdr[i].sh_size);
      if (!mod->dynstrtab) {
        set_error("Could not allocate %lu bytes for symbol string table", mod->sec_hdr[i].sh_size);
        goto err_free_load;
      }
    }
  }

  if (mod->syms == NULL || mod->dynstrtab == NULL) {
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
  free(mod->dynstrtab);
  free(mod->so_base);
  free(mod);

  return NULL;
}

static int so_relocate(dynmod_t *mod) {
  for (int i = 0; i < mod->elf_hdr->e_shnum; i++) {
    const char *sh_name = mod->shstrtab + mod->sec_hdr[i].sh_name;

    if (strcmp(sh_name, ".rela.dyn") == 0 || strcmp(sh_name, ".rela.plt") == 0) {
      Elf64_Rela *rels = (Elf64_Rela *)((uintptr_t)mod->text_base + mod->sec_hdr[i].sh_addr);

      for (int j = 0; j < mod->sec_hdr[i].sh_size / sizeof(Elf64_Rela); j++) {
        uintptr_t *ptr = (uintptr_t *)((uintptr_t)mod->text_base + rels[j].r_offset);
        Elf64_Sym *sym = &mod->syms[ELF64_R_SYM(rels[j].r_info)];

        const int type = ELF64_R_TYPE(rels[j].r_info);
        switch (type) {
          case R_AARCH64_ABS64:
            // FIXME: = or += ?
            *ptr = (uintptr_t)mod->text_virtbase + sym->st_value + rels[j].r_addend;
            break;

          case R_AARCH64_RELATIVE:
            // sometimes the value of r_addend is also at *ptr
            *ptr = (uintptr_t)mod->text_virtbase + rels[j].r_addend;
            break;

          case R_AARCH64_GLOB_DAT:
          case R_AARCH64_JUMP_SLOT:
            if (sym->st_shndx != SHN_UNDEF)
              *ptr = (uintptr_t)mod->text_virtbase + sym->st_value + rels[j].r_addend;
            break;

          case R_AARCH64_NONE:
            break; // sorry nothing

          default:
            set_error("%s: Unknown relocation type: %x", mod->name, type);
            break;
        }
      }
    }
  }

  return 0;
}

static int so_import(dynmod_t *dst, const dynmod_t *src, const int taint_missing) {
  if (src->exports == NULL || src->num_exports == 0)
    return -1;

  for (int i = 0; i < dst->elf_hdr->e_shnum; i++) {
    const char *sh_name = dst->shstrtab + dst->sec_hdr[i].sh_name;

    if (strcmp(sh_name, ".rela.dyn") == 0 || strcmp(sh_name, ".rela.plt") == 0) {
      Elf64_Rela *rels = (Elf64_Rela *)((uintptr_t)dst->text_base + dst->sec_hdr[i].sh_addr);

      for (int j = 0; j < dst->sec_hdr[i].sh_size / sizeof(Elf64_Rela); j++) {
        uintptr_t *ptr = (uintptr_t *)((uintptr_t)dst->text_base + rels[j].r_offset);
        const Elf64_Sym *sym = &dst->syms[ELF64_R_SYM(rels[j].r_info)];

        // skip shit that's already defined
        if (sym->st_shndx != SHN_UNDEF) continue;

        const int type = ELF64_R_TYPE(rels[j].r_info);
        const char *name;
        switch (type) {
          case R_AARCH64_ABS64:
          case R_AARCH64_GLOB_DAT:
          case R_AARCH64_JUMP_SLOT:
            // make it crash in a predictable way when debugging
            if (taint_missing)
              *ptr = (type == R_AARCH64_ABS64) ? 0 : rels[j].r_offset;
            name = dst->dynstrtab + sym->st_name;
            for (int k = 0; k < src->num_exports; k++) {
              if (!strcmp(name, src->exports[k].name)) {
                *ptr = (uintptr_t)src->exports[k].addr_rx + rels[j].r_addend;
                break;
              }
            }
            break;

          default:
            break;
        }
      }
    }
  }

  return 0;
}

static int so_resolve(dynmod_t *mod, const int taint_missing) {
  const dynmod_t *src = &so_list;

  // do the main module as a special case to taint symbols if needed
  so_import(mod, src, taint_missing);
  src = src->next;

  // do the rest of them that have public exports
  while (src) {
    if ((src->flags & SOLDER_GLOBAL) && src->num_exports && src->exports)
      so_import(mod, src, 0);
    src = src->next;
  }

  return 0;
}

static void so_execute_init_array(dynmod_t *mod) {
  for (int i = 0; i < mod->elf_hdr->e_shnum; i++) {
    const char *sh_name =  mod->shstrtab +  mod->sec_hdr[i].sh_name;
    if (strcmp(sh_name, ".init_array") == 0) {
      int (** init_array)() = (void *)((uintptr_t) mod->text_virtbase + mod->sec_hdr[i].sh_addr);
      for (int j = 0; j <  mod->sec_hdr[i].sh_size / 8; j++) {
        if (init_array[j] != 0)
          init_array[j]();
      }
    }
  }
}

static void so_execute_fini_array(dynmod_t *mod) {
  if (mod->fini_array) {
    for (int i = 0; i < mod->num_fini; ++i)
      mod->fini_array[i]();
  }
}

static void so_save_fini_array(dynmod_t *mod) {
  for (int i = 0; i < mod->elf_hdr->e_shnum; i++) {
    const char *sh_name =  mod->shstrtab +  mod->sec_hdr[i].sh_name;
    if (strcmp(sh_name, ".fini_array") == 0) {
      mod->fini_array = (void *)((uintptr_t) mod->text_virtbase + mod->sec_hdr[i].sh_addr);
      mod->num_fini = mod->sec_hdr[i].sh_size / 8;
      break;
    }
  }
}

static void so_free_exports(dynmod_t *mod) {
  if (!mod->exports) return;
  free(mod->exports);
  mod->num_exports = 0;
  mod->exports = NULL;
}

static void so_gen_exports(dynmod_t *mod) {
  // free old exports if necessary
  if (mod->exports)
    so_free_exports(mod);

  // TODO: what types of symbols should be visible?
  //       for now just dump everything in .dynsym that's not undefined

  mod->num_exports = 0;
  mod->exports = calloc(mod->num_syms, sizeof(*mod->exports));
  if (!mod->exports) return;

  int n = 0;
  for (int i = 0; i < mod->num_syms; ++i) {
    if (mod->syms[i].st_shndx != SHN_UNDEF) {
      mod->exports[n].name = mod->dynstrtab + mod->syms[i].st_name;
      mod->exports[n].addr_rw = mod->text_base + mod->syms[i].st_value;
      mod->exports[n].addr_rx = mod->text_virtbase + mod->syms[i].st_value;
      ++n;
    }
  }

  mod->num_exports = n;
}

static void so_flush_caches(dynmod_t *mod) {
  armDCacheFlush(mod->load_virtbase, mod->load_size);
  armICacheInvalidate(mod->load_virtbase, mod->load_size);
}

static int so_unload(dynmod_t *mod) {
  if (mod->load_base == NULL)
    return -1;

  // execute destructors, if any
  so_execute_fini_array(mod);
  mod->fini_array = NULL;
  mod->num_fini = 0;

  if (mod->so_base) {
    // someone forgot to free the temp data
    free(mod->so_base);
  }

  // remap text as RW
  const u64 text_asize = ALIGN_MEM(mod->text_size, ALIGN_PAGE); // align to page
  svcSetProcessMemoryPermission(envGetOwnProcessHandle(), (u64)mod->text_virtbase, text_asize, Perm_Rw);
  // unmap everything
  svcUnmapProcessCodeMemory(envGetOwnProcessHandle(), (u64)mod->load_virtbase, (u64)mod->load_base, mod->load_size);

  // release virtual address range
  virtmemLock();
  virtmemRemoveReservation(mod->load_memrv);
  virtmemUnlock();

  so_free_exports(mod);

  so_heap_free(mod->load_base);
  mod->load_base = NULL;

  free(mod->name);
  free(mod->dynstrtab);
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
    set_error("`%s`: svcMapProcessCodeMemory failed:\n%08x",
      mod->name, rc);
    return -1;
  }

  // map code sections as R+X
  const u64 text_asize = ALIGN_MEM(mod->text_size, ALIGN_PAGE); // align to page
  rc = svcSetProcessMemoryPermission(envGetOwnProcessHandle(), (u64)mod->text_virtbase, text_asize, Perm_Rx);
  if (R_FAILED(rc)) {
    set_error("`%s`: could not map %u bytes of RX memory at %p:\n%08x",
      mod->name, text_asize, mod->text_virtbase, rc);
    return -2;
  }

  // map the rest as R+W
  const u64 rest_asize = mod->load_size - text_asize;
  const uintptr_t rest_virtbase = (uintptr_t)mod->text_virtbase + text_asize;
  rc = svcSetProcessMemoryPermission(envGetOwnProcessHandle(), rest_virtbase, rest_asize, Perm_Rw);
  if (R_FAILED(rc)) {
    set_error("`%s`: could not map %u bytes of RW memory at %p (%p) (2):\n%08x",
      mod->name, rest_asize, mod->data_virtbase, rest_virtbase, rc);
    return -3;
  }

  return 0;
}

static int so_finalize(dynmod_t *mod) {
  // resolve all imports
  so_resolve(mod, 1);

  // try to map the module as executable
  if (so_map(mod)) return -1;

  so_flush_caches(mod);

  // save destructor pointers for later, if any
  so_save_fini_array(mod);
  so_execute_init_array(mod);

  // remove the temp data
  free(mod->so_base);
  mod->so_base = NULL;

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

  // clear main module's exports
  free(so_list.exports);
  so_list.exports = NULL;
  so_list.num_exports = 0;
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

  // make an exports table
  so_gen_exports(mod);

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

  if (mod->so_base) {
    // module isn't ready yet; try to finalize it
    if (so_finalize(mod)) {
      so_unload(mod);
      return NULL;
    }
  }

  // module has no exports
  if (!mod->exports) {
    set_error("`%s`: no exports available", mod->name);
    return NULL;
  }

  for (int i = 0; i < mod->num_exports; ++i) {
    if (!strcmp(symname, mod->exports[i].name))
      return mod->exports[i].addr_rx;
  }

  set_error("`%s`: symbol `%s` not found", mod->name, symname);
  return NULL;
}

void solder_add_main_exports(const solder_export_t *exp, const int numexp) {
  int newnumexp = so_list.num_exports + numexp;
  solder_export_t *newexp = realloc(so_list.exports, sizeof(solder_export_t) * newnumexp);
  if (newexp) {
    memcpy(newexp + so_list.num_exports, exp, sizeof(solder_export_t) * numexp);
    so_list.exports = newexp;
    so_list.num_exports = newnumexp;
    // since main now has exports, mark it global
    so_list.flags |= SOLDER_GLOBAL;
  }
}

void *solder_get_data_addr(void *handle) {
  if (!handle) {
    set_error("get_data_addr(): NULL handle");
    return NULL;
  }

  dynmod_t *mod = handle;
  if (mod->so_base == NULL) {
    set_error("`%s`: Already mapped as R/X", mod->name);
    return NULL;
  }

  return mod->data_base;
}

void *solder_get_text_addr(void *handle) {
  if (!handle) {
    set_error("get_text_addr(): NULL handle");
    return NULL;
  }

  dynmod_t *mod = handle;
  if (mod->so_base == NULL) {
    set_error("`%s`: Already mapped as R/X", mod->name);
    return NULL;
  }

  return mod->text_base;
}

int solder_hook_function(void *__restrict handle, const char *__restrict symname, void *dstaddr) {
  if (!handle) {
    set_error("hook_function(): NULL handle");
    return -1;
  }

  dynmod_t *mod = handle;
  if (mod->so_base == NULL) {
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
