#include <string.h>

#include "common.h"
#include "solder.h"
#include "util.h"
#include "exports.h"
#include "lookup.h"

const Elf64_Sym *solder_elf_hashtab_lookup(
  const char *strtab,
  const Elf64_Sym *symtab,
  const uint32_t *hashtab,
  const char *symname
) {
    const uint32_t hash = solder_elf_hash((const uint8_t *)symname);
    const uint32_t nbucket = hashtab[0];
    const uint32_t *bucket = &hashtab[2];
    const uint32_t *chain = &bucket[nbucket];
    const uint32_t bucketidx = hash % nbucket;
    for (uint32_t i = bucket[bucketidx]; i; i = chain[i]) {
      if (!strcmp(symname, strtab + symtab[i].st_name))
        return symtab + i;
    }
    return NULL;
}

const Elf64_Sym *solder_lookup_sym(const dynmod_t *mod, const char *symname) {
  if (!mod || !mod->dynsym || !mod->dynstrtab)
    return NULL;
  // if hashtab is available, use that for lookup, otherwise do linear search
  if (mod->hashtab)
    return solder_elf_hashtab_lookup(mod->dynstrtab, mod->dynsym, mod->hashtab, symname);
  // sym 0 is always UNDEF
  for (size_t i = 1; i < mod->num_dynsym; ++i) {
    if (!strcmp(symname, mod->dynstrtab + mod->dynsym[i].st_name))
      return mod->dynsym + i;
  }
  return NULL;
}

void *solder_lookup(const dynmod_t *mod, const char *symname) {
  const Elf64_Sym *sym = solder_lookup_sym(mod, symname);
  if (sym && sym->st_shndx != SHN_UNDEF)
    return (uint8_t *)mod->load_virtbase + sym->st_value;
  else
    return NULL;
}

const Elf64_Sym *solder_reverse_lookup_sym(const dynmod_t *mod, const void *addr) {
  if (!(mod->flags & MOD_RELOCATED) || !mod->dynsym || mod->num_dynsym <= 1)
    return NULL;
  // skip mandatory UNDEF
  for (size_t i = 1; i < mod->num_dynsym; ++i) {
    if (mod->dynsym[i].st_shndx != SHN_UNDEF && mod->dynsym[i].st_value) {
      const uintptr_t symaddr = mod->dynsym[i].st_value + (uintptr_t)mod->load_virtbase;
      if (symaddr == (uintptr_t)addr)
        return mod->dynsym + i;
    }
  }
  return NULL;
}

void *solder_lookup_global(const char *symname) {
  if (!symname || !*symname)
    return NULL;

  const dynmod_t *mod = &solder_dsolist;

  // try the override exports table if it exists
  if (&__solder_override_exports && &__solder_num_override_exports && __solder_override_exports) {
    for (size_t i = 0; i < __solder_num_override_exports; ++i)
      if (!strcmp(symname, __solder_override_exports[i].name))
        return __solder_override_exports[i].addr_rx;
  }

  // try actual modules
  while (mod) {
    const Elf64_Sym *sym = solder_lookup_sym(mod, symname);
    if (sym && sym->st_shndx != SHN_UNDEF)
      return (void *)((uintptr_t)mod->load_virtbase + sym->st_value);
    mod = mod->next;
  }

  // try the aux exports table if it exists
  if (&__solder_aux_exports && &__solder_num_aux_exports && __solder_aux_exports) {
    for (size_t i = 0; i < __solder_num_aux_exports; ++i)
      if (!strcmp(symname, __solder_aux_exports[i].name))
        return __solder_aux_exports[i].addr_rx;
  }

  return NULL;
}
