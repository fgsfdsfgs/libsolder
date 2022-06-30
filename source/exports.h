#pragma once

#include <stdint.h>
#include <elf.h>
#include "solder.h"

// optional user-defined global exports
extern __attribute__((weak)) const solder_export_t *__solder_aux_exports;
extern __attribute__((weak)) const size_t __solder_num_aux_exports;

uint32_t solder_elf_hash(const uint8_t *name);

const Elf64_Sym *solder_elf_hashtab_lookup(
  const char *strtab,
  const Elf64_Sym *symtab,
  const uint32_t *hashtab,
  const char *symname
);

int solder_symtab_from_nro(
  Elf64_Sym **out_symtab,
  char **out_strtab,
  uint32_t **out_hashtab
);

int solder_symtab_from_exports(
  const solder_export_t *exp,
  const int numexp,
  Elf64_Sym **out_symtab,
  char **out_strtab,
  uint32_t **out_hashtab
);
