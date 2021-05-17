#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define MAX_ERROR 2048

static char errbuf[MAX_ERROR];
static const char *err = NULL;

void set_error(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  if (!err) {
    vsnprintf(errbuf, sizeof(errbuf), fmt, args);
    err = errbuf;
    printf("solder error: %s\n", err);
  }
  va_end(args);
}

const char *solder_dlerror(void) {
  const char *ret = err;
  err = NULL;
  return ret;
}

char *ustrdup(const char *s) {
  const size_t len = strlen(s);
  char *ns = malloc(len + 1);
  if (ns) memcpy(ns, s, len + 1);
  return ns;
}

void *umemdup(const void *src, const size_t size) {
  void *dst = malloc(size);
  if (dst) memcpy(dst, src, size);
  return dst;
}
