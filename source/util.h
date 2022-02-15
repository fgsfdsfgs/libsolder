#pragma once

#include <stdlib.h>
#include <stdio.h>

#ifdef DEBUG
#define DEBUG_PRINTF(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_PRINTF(...)
#endif

#define ALIGN_MEM(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#define ALIGN_PAGE 0x1000

void solder_set_error(const char *fmt, ...);

char *solder_strdup(const char *s);
void *solder_memdup(const void *src, const size_t size);

uint32_t solder_elf_hash(const uint8_t *name);
