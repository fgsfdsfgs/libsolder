#pragma once

#include "common.h"

const Elf64_Sym *solder_lookup_sym(const dynmod_t *mod, const char *symname);
const Elf64_Sym *solder_reverse_lookup_sym(const dynmod_t *mod, const void *addr);

void *solder_lookup(const dynmod_t *mod, const char *symname);
void *solder_lookup_global(const char *symname);
