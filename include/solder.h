#pragma once

#ifdef __cplusplus
extern "C" {
#endif

enum solder_init_flags {
  SOLDER_INIT_EXPORTS = 1, /* populate main exports table with some internal exports */
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
  void *addr_rw;     /* writable address (you don't need to fill this in) */
} solder_export_t;

#define SOLDER_EXPORT_SYMBOL(sym) { #sym, (void *)&sym }
#define SOLDER_EXPORT(name, addr) { name, addr }

/* initialize loader, allocating `heapsize` bytes for dynamic libs
   if heapsize is <= 0, sets the internal default of 32MB */
int solder_init(const int heapsize, const int flags);
/* deinit loader and free all libraries and library heap */
void solder_quit(void);

/* these function mostly the same as the equivalent dlfcn stuff */

void *solder_dlopen(const char *fname, int flags);
int solder_dlclose(void *handle);
void *solder_dlsym(void *__restrict handle, const char *__restrict symname);
/* return current error and reset the error flag */
const char *solder_dlerror(void);

/* append exports to the main module's export list; addr_rw doesn't need to be set */
void solder_add_main_exports(const solder_export_t *exp, const int numexp);

/* these only work on modules that haven't been finalized, so use LAZY */

/* get data seg address (writable) */
void *solder_get_data_addr(void *handle);
/* get text seg address (writable) */
void *solder_get_text_addr(void *handle);
/* replace code at `symname` with branch to another function at `dstaddr` */
int solder_hook_function(void *__restrict handle, const char *__restrict symname, void *dstaddr);

#ifdef __cplusplus
}
#endif
