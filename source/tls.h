#pragma once

#include "common.h"

__attribute__((weak)) intptr_t solder_tls_resolve_static(intptr_t ofs);
__attribute__((weak)) intptr_t solder_tls_resolve_tlsdesc(void **desc);

int solder_tls_alloc(dynmod_t *mod);
void solder_tls_free(dynmod_t *mod);