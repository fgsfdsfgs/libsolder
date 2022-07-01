#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <limits.h>

#include "common.h"
#include "solder.h"
#include "util.h"
#include "exports.h"
#include "lookup.h"
#include "reloc.h"
#include "tls.h"
#include "loader.h"

// total modules loaded
static int so_num_modules = 0;

dynmod_t *solder_dso_load(const char *filename, const char *modname) {
  size_t so_size = 0;
  Elf64_Ehdr *ehdr = NULL;
  Elf64_Phdr *phdr = NULL;
  Elf64_Shdr *shdr = NULL;
  char *shstrtab = NULL;

  dynmod_t *mod = calloc(1, sizeof(dynmod_t));
  if (!mod) {
    solder_set_error("Could not allocate dynmod header");
    return NULL;
  }

  // try cwd, then all search paths
  char tmppath[PATH_MAX] = { 0 };
  FILE *fd = fopen(filename, "rb");
  struct searchpath *spath = solder_searchlist;
  while (spath && !fd) {
    snprintf(tmppath, sizeof(tmppath), "%s/%s", spath->path, filename);
    fd = fopen(tmppath, "rb");
    if (fd) DEBUG_PRINTF("`%s`: found at `%s`\n", modname, tmppath);
    spath = spath->next;
  }

  if (fd == NULL) {
    solder_set_error("Could not open `%s`", filename);
    free(mod);
    return NULL;
  }

  fseek(fd, 0, SEEK_END);
  so_size = ftell(fd);
  fseek(fd, 0, SEEK_SET);

  DEBUG_PRINTF("`%s`: total elf size is %lu\n", filename, so_size);

  ehdr = memalign(ALIGN_PAGE, so_size);
  if (!ehdr) {
    solder_set_error("Could not allocate %lu bytes for `%s`", so_size, filename);
    fclose(fd);
    free(mod);
    return NULL;
  }

  fread(ehdr, so_size, 1, fd);
  fclose(fd);

  if (memcmp(ehdr, ELFMAG, SELFMAG) != 0) {
    solder_set_error("`%s` is not a valid ELF file", filename);
    goto err_free_so;
  }

  phdr = (Elf64_Phdr *)((uintptr_t)ehdr + ehdr->e_phoff);
  shdr = (Elf64_Shdr *)((uintptr_t)ehdr + ehdr->e_shoff);
  shstrtab = (char *)((uintptr_t)ehdr + shdr[ehdr->e_shstrndx].sh_offset);

  // calculate total size of the LOAD segments (overshoot it by a ton actually)
  // total size = size of last load segment + vaddr of last load segment
  size_t max_align = ALIGN_PAGE;
  for (size_t i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD && phdr[i].p_memsz) {
      const size_t this_size = phdr[i].p_vaddr + phdr[i].p_memsz;
      if (this_size > mod->load_size) mod->load_size = this_size;
      if (phdr[i].p_align > max_align) max_align = phdr[i].p_align;
      ++mod->num_segs;
    }
  }

  // round up to max segment alignment
  mod->load_size = ALIGN_MEM(mod->load_size, max_align);

  DEBUG_PRINTF("`%s`: total memory reserved %lu; %lu segs total\n", filename, mod->load_size, mod->num_segs);

  // reserve virtual memory space for the entire LOAD zone while we're fucking with the ELF
  virtmemLock();
  mod->load_virtbase = virtmemFindCodeMemory(mod->load_size, ALIGN_PAGE);
  mod->load_memrv = virtmemAddReservation(mod->load_virtbase, mod->load_size);
  virtmemUnlock();

  // collect segments
  mod->segs = calloc(mod->num_segs, sizeof(*mod->segs));
  if (!mod->segs) {
    solder_set_error("Could not allocate space for `%s`'s segment table", filename);
    goto err_free_load;
  }
  for (size_t i = 0, n = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD && phdr[i].p_memsz) {
      if (phdr[i].p_flags & PF_R) mod->segs[n].pflags |= Perm_R;
      if (phdr[i].p_flags & PF_W) mod->segs[n].pflags |= Perm_W;
      if (phdr[i].p_flags & PF_X) mod->segs[n].pflags |= Perm_X;
      mod->segs[n].align = (phdr[i].p_align < ALIGN_PAGE) ? ALIGN_PAGE : phdr[i].p_align;
      mod->segs[n].virtbase = (void *)((Elf64_Addr)mod->load_virtbase + phdr[i].p_vaddr);
      mod->segs[n].virtpage = (void *)ALIGN_DN((Elf64_Addr)mod->segs[n].virtbase, mod->segs[n].align);
      mod->segs[n].virtend = (void *)ALIGN_MEM((Elf64_Addr)mod->segs[n].virtbase + phdr[i].p_memsz, mod->segs[n].align);
      mod->segs[n].size = (Elf64_Addr)mod->segs[n].virtend - (Elf64_Addr)mod->segs[n].virtpage;
      // create an aligned copy of the segment
      mod->segs[n].page = memalign(mod->segs[n].align, mod->segs[n].size);
      if (!mod->segs[n].page) {
        solder_set_error("Could not allocate `%lu` bytes for segment %lu\n", mod->segs[n].size, n);
        goto err_free_load;
      }
      const intptr_t diff = (Elf64_Addr)mod->segs[n].virtbase - (Elf64_Addr)mod->segs[n].virtpage;
      mod->segs[n].base = (void *)((Elf64_Addr)mod->segs[n].page + diff);
      mod->segs[n].end = mod->segs[n].page + mod->segs[n].size;
      // zero it out and fill it in
      memset(mod->segs[n].page, 0, mod->segs[n].size);
      memcpy(mod->segs[n].base, (void *)((uintptr_t)ehdr + phdr[i].p_offset), phdr[i].p_filesz);
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
    solder_set_error("`%s` doesn't have a DYNAMIC segment", filename);
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
    } else if (!strcmp(sh_name, ".got")) {
      mod->got = (void *)((Elf64_Addr)mod->load_virtbase + shdr[i].sh_addr);
      mod->num_got = shdr[i].sh_size / sizeof(void *);
    }
  }

  if (mod->dynsym == NULL || mod->dynstrtab == NULL) {
    solder_set_error("No symbol information in `%s`", filename);
    goto err_free_load;
  }

  mod->name = solder_strdup(modname);
  mod->type = ehdr->e_type;
  if (mod->type == ET_EXEC) {
    mod->entry = mod->load_virtbase + ehdr->e_entry;
    DEBUG_PRINTF("`%s`: is executable: entry at %p\n", modname, mod->entry);
  }

  so_num_modules++;

  free(ehdr); // don't need this no more

  return mod;

err_free_load:
  virtmemLock();
  virtmemRemoveReservation(mod->load_memrv);
  virtmemUnlock();
  for (size_t i = 0; i < mod->num_segs; ++i)
    free(mod->segs[i].page);
err_free_so:
  free(mod->segs);
  free(ehdr);
  free(mod);

  return NULL;
}

static int dso_map(dynmod_t *mod) {
  Result rc = 0;
  Handle self = envGetOwnProcessHandle();
  for (size_t i = 0; i < mod->num_segs; ++i) {
    rc = svcMapProcessCodeMemory(self, (u64)mod->segs[i].virtpage, (u64)mod->segs[i].page, mod->segs[i].size);
    if (R_FAILED(rc)) {
      solder_set_error("`%s`: svcMapProcessCodeMemory failed on seg %lu:\n%08x", mod->name, i, rc);
      goto err_free_unmap;
    }
    rc = svcSetProcessMemoryPermission(self, (u64)mod->segs[i].virtpage, mod->segs[i].size, mod->segs[i].pflags);
    if (R_FAILED(rc)) {
      solder_set_error("`%s`: svcSetProcessMemoryPermission failed on seg %lu:\n%08x", mod->name, i, rc);
      goto err_free_unmap;
    }
  }

  mod->flags |= MOD_MAPPED;

  DEBUG_PRINTF("`%s`: mapped to %p - %p\n", mod->name, mod->load_virtbase, mod->load_virtbase + mod->load_size);

  return 0;

err_free_unmap:
  for (size_t i = 0; i < mod->num_segs; ++i)
    svcUnmapProcessCodeMemory(self, (u64)mod->segs[i].virtpage, (u64)mod->segs[i].page, mod->segs[i].size);
  return -1;
}

static void dso_initialize(dynmod_t *mod) {
  if (mod->init_array) {
    DEBUG_PRINTF("`%s`: init array %p has %lu entries\n", mod->name, mod->init_array, mod->num_init);
    for (size_t i = 0; i < mod->num_init; ++i)
      if (mod->init_array[i])
        mod->init_array[i]();
  }
  mod->flags |= MOD_INITIALIZED;
}

static void dso_finalize(dynmod_t *mod) {
  if (mod->fini_array) {
    DEBUG_PRINTF("`%s`: fini array %p has %lu entries\n", mod->name, mod->fini_array, mod->num_fini);
    for (size_t i = 0; i < mod->num_fini; ++i)
      if (mod->fini_array[i])
        mod->fini_array[i]();
    mod->fini_array = NULL;
    mod->num_fini = 0;
  }
  mod->flags &= ~MOD_INITIALIZED;
}

static void dso_link(dynmod_t *mod) {
  mod->next = solder_dsolist.next;
  mod->prev = &solder_dsolist;
  if (solder_dsolist.next)
    solder_dsolist.next->prev = mod;
  solder_dsolist.next = mod;
}

static void dso_unlink(dynmod_t *mod) {
  if (mod->prev)
    mod->prev->next = mod->next;
  if (mod->next)
    mod->next->prev = mod->prev;
  mod->next = NULL;
  mod->prev = NULL;
}

static int dso_relocate_and_init(dynmod_t *mod, int ignore_undef) {
  if (!(mod->flags & MOD_MAPPED))
    dso_map(mod);
  if (!(mod->flags & MOD_RELOCATED) && solder_relocate(mod, ignore_undef, 0))
    return -1;
  if (!(mod->flags & MOD_INITIALIZED))
    dso_initialize(mod);
  dso_link(mod);
  return 0;
}

static void dso_relocate_and_init_all(int ignore_undef) {
  DEBUG_PRINTF("dso_relocate_and_init_all(): processing %d loaded modules\n", so_num_modules);

  int not_relocated = 0;

  DEBUG_PRINTF("* mapping modules\n");
  for (dynmod_t *p = solder_dsolist.next; p; p = p->next) {
    if (!(p->flags & MOD_MAPPED))
      dso_map(p);
  }

  DEBUG_PRINTF("* relocating modules\n");
  for (dynmod_t *p = solder_dsolist.next; p; p = p->next) {
    if (!(p->flags & MOD_RELOCATED)) {
      if (solder_relocate(p, ignore_undef, 0)) {
        DEBUG_PRINTF("* could not relocate `%s` yet\n", p->name);
        not_relocated++;
      } else {
        DEBUG_PRINTF("* relocated `%s`\n", p->name);
      }
    }
  }

  if (not_relocated)
    DEBUG_PRINTF("* warning: %d modules not relocated\n", not_relocated);

  for (dynmod_t *p = solder_dsolist.next; p; p = p->next) {
    if ((p->flags & MOD_RELOCATED) && !(p->flags & MOD_INITIALIZED)) {
      DEBUG_PRINTF("* initializing `%s`\n", p->name);
      dso_initialize(p);
    }
  }
}

static void dep_scan(dynmod_t *mod);

static dynmod_t *dep_load(dynmod_t *parent, const char *depname) {
  dynmod_t *mod = NULL;

  // chop off path, if any
  char *slash = strrchr(depname, '/');
  if (slash) depname = slash + 1;

  // see if the module is already loaded and just increase refcount if it is
  for (dynmod_t *p = solder_dsolist.next; p; p = p->next) {
    if (!strcmp(p->name, depname)) {
      mod = p;
      break;
    }
  }

  if (mod) {
    DEBUG_PRINTF("dep_load(%s, %s): `%s` already loaded\n", parent->name, depname, mod->name);
    mod->refcount++;
    mod->flags |= SOLDER_GLOBAL;
    return mod;
  }

  DEBUG_PRINTF("dep_load(%s, %s): trying `%s`\n", parent->name, depname, depname);
  mod = solder_dso_load(depname, depname);
  if (mod) {
    mod->flags |= SOLDER_LAZY | SOLDER_GLOBAL;
    mod->refcount = 1;
    dso_link(mod); // link it early
    dep_scan(mod); // scan it for deps
  } else {
    DEBUG_PRINTF("dep_load(%s, %s): failed to find dep\n", parent->name, depname);
  }

  // clear error flag
  solder_dlerror();

  return mod;
}

static void dep_scan(dynmod_t *mod) {
  if (!mod || !mod->dynamic) {
    DEBUG_PRINTF("`%s`: NULL dynamic\n", mod ? mod->name : "(null)");
    return;
  }

  DEBUG_PRINTF("`%s`: scanning for deps\n", mod->name);

  const Elf64_Dyn *dyn = mod->dynamic;

  // find strtab
  const char *strtab = NULL;
  for (; dyn->d_tag != DT_NULL; dyn++) {
    if (dyn->d_tag == DT_STRTAB) {
      strtab = (const char *)(mod->load_virtbase + dyn->d_un.d_ptr);
      break;
    }
  }

  if (strtab == NULL) {
    DEBUG_PRINTF("`%s`: could not find strtab\n", mod->name);
    return;
  }

  // find all DT_NEEDED modules and start loading them
  for (dyn = mod->dynamic; dyn->d_tag != DT_NULL; dyn++) {
    if (dyn->d_tag == DT_NEEDED) {
      const char *dep_modname = strtab + dyn->d_un.d_val;
      dep_load(mod, dep_modname);
    }
  }
}

int solder_dso_unload(dynmod_t *mod) {
  if (mod->load_base == NULL)
    return -1;

  DEBUG_PRINTF("`%s`: unloading\n", mod->name);

  // execute destructors, if any
  if (mod->flags & MOD_INITIALIZED)
    dso_finalize(mod);

  // free TLS block
  solder_tls_free(mod);

  DEBUG_PRINTF("`%s`: unmapping\n", mod->name);

  // unmap and free all segs
  Handle self = envGetOwnProcessHandle();
  Result rc;
  for (size_t i = 0; i < mod->num_segs; ++i) {
    // restore permissions if needed (maybe not needed at all)
    if (mod->segs[i].pflags != Perm_Rw) {
      rc = svcSetProcessMemoryPermission(self, (u64)mod->segs[i].virtpage, mod->segs[i].size, Perm_Rw);
      if (R_FAILED(rc)) DEBUG_PRINTF("* svcSetProcessMemoryPermission(seg %lu): error %08x\n", i, rc);
    }
    rc = svcUnmapProcessCodeMemory(self, (u64)mod->segs[i].virtpage, (u64)mod->segs[i].page, mod->segs[i].size);
    if (R_FAILED(rc)) DEBUG_PRINTF("* svcUnmapProcessCodeMemory(seg %lu): error %08x\n", i, rc);
    free(mod->segs[i].page);
    mod->segs[i].base = NULL;
    mod->segs[i].page = NULL;
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

  so_num_modules--;
  DEBUG_PRINTF("`%s`: unloaded\n", mod->name);

  // free everything else
  free(mod->segs);
  free(mod->name);
  free(mod);

  return 0;
}

void solder_unload_all(void) {
  dynmod_t *mod = solder_dsolist.next;
  solder_dsolist.next = NULL;

  while (mod) {
    dynmod_t *next = mod->next;
    solder_dso_unload(mod);
    mod = next;
  }

  // clear main module's exports if needed
  if (solder_dsolist.flags & MOD_OWN_SYMTAB) {
    free(solder_dsolist.dynsym); solder_dsolist.dynsym = NULL;
    free(solder_dsolist.dynstrtab); solder_dsolist.dynstrtab = NULL;
    free(solder_dsolist.hashtab); solder_dsolist.hashtab = NULL;
    solder_dsolist.flags &= ~MOD_OWN_SYMTAB;
  }
}

void solder_autoload(void) {
  // load main module's dependencies recursively
  dep_scan(&solder_dsolist);
  // relocate and initialize all modules we just loaded
  dso_relocate_and_init_all(solder_init_flags() & SOLDER_ALLOW_UNDEFINED);
  // resolve imports in the main module if dynsym info is available
  if (solder_dsolist.dynstrtab && solder_dsolist.dynsym) {
    DEBUG_PRINTF("solder_autoload(): patching main module imports\n");
    solder_relocate(&solder_dsolist, 1, 1);
  }
  DEBUG_PRINTF("solder_autoload(): autoloaded %d deps\n", so_num_modules);
  // clear error flag
  solder_dlerror();
}

/* libsolder API begins */

void *solder_dlopen(const char *fname, int flags) {
  dynmod_t *mod = NULL;

  // see if the module is already loaded and just increase refcount if it is
  for (dynmod_t *p = solder_dsolist.next; p; p = p->next) {
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
  mod = solder_dso_load(fname, fname);
  if (!mod) return NULL;

  // load its dependencies if allowed
  if (!(flags & SOLDER_NO_AUTOLOAD)) {
    dep_scan(mod);
    // relocate everything that was just loaded
    dso_relocate_and_init_all(0);
  }

  // relocate and init it right away if not lazy
  if (!(flags & SOLDER_LAZY)) {
    if (dso_relocate_and_init(mod, 0)) {
      solder_dso_unload(mod);
      return NULL;
    }
  }

  mod->flags |= flags;
  mod->refcount = 1;

  return mod;
}

int solder_dlclose(void *handle) {
  if (!handle) {
    solder_set_error("dlclose(): NULL handle");
    return -1;
  }

  dynmod_t *mod = handle;
  // free the module when reference count reaches zero
  if (--mod->refcount <= 0) {
    DEBUG_PRINTF("`%s`: refcount is 0, unloading\n", mod->name);
    dso_unlink(mod);
    return solder_dso_unload(mod);
  }

  return 0;
}

void *solder_dlsym(void *__restrict handle, const char *__restrict symname) {
  if (!symname || symname[0] == '\0') {
    solder_set_error("dlsym(): empty symname");
    return NULL;
  }

  // NULL handle means search in order starting with the main module
  dynmod_t *mod = handle ? handle : &solder_dsolist;
  for (; mod; mod = mod->next) {
    if (!(mod->flags & MOD_RELOCATED)) {
      // module isn't ready yet; try to finalize it
      if (dso_relocate_and_init(mod, 0)) {
        solder_dso_unload(mod);
        if (handle)
          return NULL;
        else
          continue;
      }
    }

    // module has no exports
    if (!mod->dynsym || mod->num_dynsym <= 1) {
      if (handle) {
        solder_set_error("`%s`: no exports available", mod->name);
        return NULL;
      } else {
        // continue searching if we're not searching in a specific lib
        continue;
      }
    }

    const Elf64_Sym *sym = solder_lookup_sym(mod, symname);
    if (sym) return (void *)((uintptr_t)mod->load_virtbase + sym->st_value);

    // stop early if we're searching in a specific module
    if (handle) {
      solder_set_error("`%s`: symbol `%s` not found", mod->name, symname);
      return NULL;
    }
  }

  solder_set_error("symbol `%s` not found in any loaded modules", symname);
  return NULL;
}

int solder_dladdr(void *addr, solder_dl_info_t *info) {
  if (!addr || !info) {
    solder_set_error("solder_dladdr(): NULL args\n");
    return 0;
  }

  // by man description only these two fields need to be NULL
  info->dli_saddr = NULL;
  info->dli_sname = NULL;

  // ha-ha, time for linear lookup
  // start with the first loaded module after main, since someone's unlikely to be looking for symbol names inside main
  const Elf64_Sym *sym = NULL;
  const dynmod_t *mod;
  for (mod = solder_dsolist.next; mod; mod = mod->next) {
    sym = solder_reverse_lookup_sym(mod, addr);
    if (sym) {
      info->dli_fname = mod->name;
      info->dli_fbase = mod->load_virtbase;
      info->dli_saddr = (void *)((uintptr_t)mod->load_virtbase + sym->st_value);
      info->dli_sname = mod->dynstrtab + sym->st_name;
      return 1;
    }
  }

  // do main module last
  mod = &solder_dsolist;
  sym = solder_reverse_lookup_sym(mod, addr);
  if (sym) {
    info->dli_fname = mod->name;
    info->dli_fbase = mod->load_virtbase;
    info->dli_saddr = (void *)((uintptr_t)mod->load_virtbase + sym->st_value);
    info->dli_sname = mod->dynstrtab + sym->st_name;
    return 1;
  }

  return 0;
}

void *solder_get_data_addr(void *handle) {
  if (!handle) {
    solder_set_error("solder_get_data_addr(): NULL handle");
    return NULL;
  }

  dynmod_t *mod = handle;
  // find data-looking segment
  for (size_t i = 0; i < mod->num_segs; ++i)
    if (mod->segs[i].pflags == Perm_R)
      return (mod->flags & MOD_MAPPED) ? mod->segs[i].virtbase : mod->segs[i].base;

  return NULL;
}

void *solder_get_text_addr(void *handle) {
  if (!handle) {
    solder_set_error("solder_get_text_addr(): NULL handle");
    return NULL;
  }

  dynmod_t *mod = handle;
  // find text-looking segment
  for (size_t i = 0; i < mod->num_segs; ++i)
    if (mod->segs[i].pflags == Perm_Rx)
      return (mod->flags & MOD_MAPPED) ? mod->segs[i].virtbase : mod->segs[i].base;

  return NULL;
}

void *solder_get_base_addr(void *handle) {
  if (!handle) {
    solder_set_error("solder_get_base_addr(): NULL handle");
    return NULL;
  }
  dynmod_t *mod = handle;
  return (mod->flags & MOD_MAPPED) ? mod->load_virtbase : mod->load_base;
}

void *solder_get_entry_addr(void *handle) {
  if (!handle) {
    solder_set_error("solder_get_entry_addr(): NULL handle");
    return NULL;
  }

  dynmod_t *mod = handle;
  if (mod->type == ET_EXEC) {
    void *ret = mod->entry;
    if (!(mod->flags & MOD_MAPPED))
      ret = ret - mod->load_virtbase + mod->load_base;
  } else {
    solder_set_error("solder_get_entry_addr(): not an executable");
  }

  return NULL;
}

int solder_hook_offset(void *__restrict handle, unsigned long long ofs, void *dstaddr) {
  if (!handle) {
    solder_set_error("solder_hook_offset(): NULL handle");
    return -1;
  }

  dynmod_t *mod = handle;
  if (!mod->load_base) return -3;

  uint32_t *srcaddr = ((mod->flags & MOD_MAPPED) ? mod->load_virtbase : mod->load_base) + ofs;

  srcaddr[0] = 0x58000051u; // LDR X17, #0x8
  srcaddr[1] = 0xd61f0220u; // BR X17
  *(uint64_t *)(srcaddr + 2) = (uint64_t)dstaddr;

  return 0;
}

int solder_hook_function(void *__restrict handle, const char *__restrict symname, void *dstaddr) {
  if (!handle) {
    solder_set_error("solder_hook_function(): NULL handle");
    return -1;
  }

  dynmod_t *mod = handle;
  if (!mod->load_base) return -2;

  uint32_t *srcaddr = solder_dlsym(handle, symname);
  if (!srcaddr) return -3;

  if (!(mod->flags & MOD_MAPPED))
    srcaddr = (void *)srcaddr - mod->load_virtbase + mod->load_base;

  srcaddr[0] = 0x58000051u; // LDR X17, #0x8
  srcaddr[1] = 0xd61f0220u; // BR X17
  *(uint64_t *)(srcaddr + 2) = (uint64_t)dstaddr;

  return 0;
}
