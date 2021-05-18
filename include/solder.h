#pragma once

#ifdef __cplusplus
extern "C" {
#endif

enum solder_init_flags {
  SOLDER_INITIALIZED = 1,    /* library is operational */
  SOLDER_NO_NRO_EXPORTS = 2, /* don't autoexport NRO symbols */
};

enum solder_dlopen_flags {
  SOLDER_LOCAL  = 0, /* don't use this module's symbols when resolving others */
  SOLDER_GLOBAL = 1, /* use this module's symbols when resolving others */
  SOLDER_NOW    = 2, /* finalize loading before dlopen() returns */
  SOLDER_LAZY   = 4, /* finalize loading only after dlsym() is called */
};

typedef struct solder_export {
  const char *name;  /* symbol name */
  void *addr_rx;     /* executable address */
} solder_export_t;

#define SOLDER_EXPORT_SYMBOL(sym) { #sym, (void *)&sym }
#define SOLDER_EXPORT(name, addr) { name, addr }

/* default export table in case you need it when using SOLDER_NO_NRO_EXPORTS */
extern const int solder_num_default_exports;
extern const solder_export_t solder_default_exports[];

/* initialize loader, allocating `heapsize` bytes for dynamic libs
   if heapsize is <= 0, sets the internal default of 32MB */
int solder_init(const int heapsize, const int flags);
/* deinit loader and free all libraries and library heap */
void solder_quit(void);
/* returns the `flags` value with which library was initialized, or 0 if it wasn't */
int solder_init_flags(void);

/* these function mostly the same as the equivalent dlfcn stuff */

void *solder_dlopen(const char *fname, int flags);
int solder_dlclose(void *handle);
void *solder_dlsym(void *__restrict handle, const char *__restrict symname);
/* return current error and reset the error flag */
const char *solder_dlerror(void);

/* set main module's dynsym list; if exp is NULL tries to get dynsyms from NRO */
int solder_set_main_exports(const solder_export_t *exp, const int numexp);

/* these only work on modules that haven't been finalized, so use LAZY */

/* get data seg address (writable) */
void *solder_get_data_addr(void *handle);
/* get text seg address (writable) */
void *solder_get_text_addr(void *handle);
/* replace code at `symname` with branch to another function at `dstaddr` */
int solder_hook_function(void *__restrict handle, const char *__restrict symname, void *dstaddr);

#ifdef SOLDER_LIBDL_COMPAT

/* provide "compatibility layer" with libdl */

#undef dlopen
#undef dlclose
#undef dlsym
#undef dlerror
#undef RTLD_LOCAL
#undef RTLD_GLOBAL
#undef RTLD_NOW
#undef RTLD_LAZY

#define dlopen(x, y) solder_dlopen((x), (y))
#define dlclose(x)   solder_dlclose((x))
#define dlsym(x, y)  solder_dlsym((x), (y))
#define dlerror()    solder_dlerror()

#define RTLD_LOCAL   SOLDER_LOCAL
#define RTLD_GLOBAL  SOLDER_GLOBAL
#define RTLD_NOW     SOLDER_NOW
#define RTLD_LAZY    SOLDER_LAZY

#endif

#ifdef __cplusplus
}
#endif
