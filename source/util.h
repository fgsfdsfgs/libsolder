#pragma once

#include <stdlib.h>
#include <stdio.h>

#ifdef DEBUG
#define DEBUG_PRINTF(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)
#else
#define DEBUG_PRINTF(fmt, ...)
#endif

#define ALIGN_MEM(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#define ALIGN_PAGE 0x1000

void set_error(const char *fmt, ...);

char *ustrdup(const char *s);
void *umemdup(const void *src, const size_t size);
