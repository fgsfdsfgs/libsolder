#pragma once

#include <stdint.h>
#include <elf.h>
#include "solder.h"

uint32_t elf_hash(const uint8_t *name);

const Elf64_Sym *elf_hashtab_lookup(
  const char *strtab,
  const Elf64_Sym *symtab,
  const uint32_t *hashtab,
  const char *symname
);

int symtab_from_nro(
  Elf64_Sym **out_symtab,
  char **out_strtab,
  uint32_t **out_hashtab
);

int symtab_from_exports(
  const solder_export_t *exp,
  const int numexp,
  Elf64_Sym **out_symtab,
  char **out_strtab,
  uint32_t **out_hashtab
);
