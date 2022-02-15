#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "util.h"

#define MAX_ERROR 2048

static char errbuf[MAX_ERROR];
static const char *err = NULL;

void solder_set_error(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  if (!err) {
    vsnprintf(errbuf, sizeof(errbuf), fmt, args);
    err = errbuf;
    DEBUG_PRINTF("solder error: %s\n", err);
  }
  va_end(args);
}

const char *solder_dlerror(void) {
  const char *ret = err;
  err = NULL;
  return ret;
}

char *solder_strdup(const char *s) {
  const size_t len = strlen(s);
  char *ns = malloc(len + 1);
  if (ns) memcpy(ns, s, len + 1);
  return ns;
}

void *solder_memdup(const void *src, const size_t size) {
  void *dst = malloc(size);
  if (dst) memcpy(dst, src, size);
  return dst;
}

uint32_t solder_elf_hash(const uint8_t *name) {
  uint64_t h = 0, g;
  while (*name) {
    h = (h << 4) + *name++;
    if ((g = (h & 0xf0000000)) != 0)
      h ^= g >> 24;
    h &= 0x0fffffff;
  }
  return h;
}
