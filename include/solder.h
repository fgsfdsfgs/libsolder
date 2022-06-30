#pragma once

#ifdef __cplusplus
extern "C" {
#endif

enum solder_init_flags {
  SOLDER_INITIALIZED     = 1, /* library is operational */
  SOLDER_NO_NRO_EXPORTS  = 2, /* don't autoexport NRO symbols */
  SOLDER_MAIN_AUTOLOAD   = 4, /* automatically load main NRO's dependencies */
  SOLDER_ALLOW_UNDEFINED = 8, /* ignore leftover undefined refs after relocating main NRO's deps */
};

enum solder_dlopen_flags {
  SOLDER_LOCAL       = 0, /* don't use this module's symbols when resolving others */
  SOLDER_GLOBAL      = 1, /* use this module's symbols when resolving others */
  SOLDER_NOW         = 2, /* finalize loading before dlopen() returns */
  SOLDER_LAZY        = 4, /* finalize loading only after dlsym() is called */
  SOLDER_NO_AUTOLOAD = 8, /* don't automatically load dependencies */
};

typedef struct solder_export {
  const char *name;  /* symbol name */
  void *addr_rx;     /* executable address */
} solder_export_t;

/* this is just Dl_info */
typedef struct solder_dl_info {
  const char *dli_fname;  /* pathname of shared object that contains address */
  void *dli_fbase;        /* base address at which shared object is loaded */
  const char *dli_sname;  /* name of symbol whose definition overlaps addr */
  void *dli_saddr;        /* exact address of symbol named in dli_sname */
} solder_dl_info_t;

#define SOLDER_EXPORT_SYMBOL(sym) { #sym, (void *)&sym }
#define SOLDER_EXPORT(name, addr) { name, addr }

/* special handle meaning "this module" */
#define SOLDER_DEFAULT (NULL)

/* default export table in case you need it when using SOLDER_NO_NRO_EXPORTS */
extern const int solder_num_default_exports;
extern const solder_export_t solder_default_exports[];

/* initialize loader */
int solder_init(const int flags);
/* deinit loader and free all libraries and library heap */
void solder_quit(void);
/* returns the `flags` value with which library was initialized, or 0 if it wasn't */
int solder_init_flags(void);
/* adds a search path; search paths are searched in reverse order, starting with `.` */
int solder_add_search_path(const char *path);
/* clear search paths */
void solder_clear_search_paths(void);

/* these function mostly the same as the equivalent dlfcn stuff */

void *solder_dlopen(const char *fname, int flags);
int solder_dlclose(void *handle);
void *solder_dlsym(void *__restrict handle, const char *__restrict symname);
/* return current error and reset the error flag */
const char *solder_dlerror(void);

/* set main module's dynsym list; if exp is NULL tries to get dynsyms from NRO */
int solder_set_main_exports(const solder_export_t *exp, const int numexp);

/* these only work on modules that haven't been finalized, so use LAZY */

/* get data seg address (r/o) */
void *solder_get_data_addr(void *handle);
/* get text seg address (r/x) */
void *solder_get_text_addr(void *handle);
/* get module base */
void *solder_get_base_addr(void *handle);
/* get entry point address (if executable) */
void *solder_get_entry_addr(void *handle);
/* replace code at `symname` with branch to another function at `dstaddr` */
int solder_hook_function(void *__restrict handle, const char *__restrict symname, void *dstaddr);
/* reverse lookup symbol name by its address */
int solder_dladdr(void *addr, solder_dl_info_t *info);

#ifdef SOLDER_LIBDL_COMPAT

/* provide "compatibility layer" with libdl */

#undef dlopen
#undef dlclose
#undef dlsym
#undef dlerror
#undef dladdr
#undef RTLD_LOCAL
#undef RTLD_GLOBAL
#undef RTLD_NOW
#undef RTLD_LAZY
#undef RTLD_DEFAULT

#define dlopen(x, y) solder_dlopen((x), (y))
#define dlclose(x)   solder_dlclose((x))
#define dlsym(x, y)  solder_dlsym((x), (y))
#define dladdr(x, y) solder_dladdr((x), (y))
#define dlerror()    solder_dlerror()

#define RTLD_LOCAL   SOLDER_LOCAL
#define RTLD_GLOBAL  SOLDER_GLOBAL
#define RTLD_NOW     SOLDER_NOW
#define RTLD_LAZY    SOLDER_LAZY
#define RTLD_DEFAULT SOLDER_DEFAULT

typedef solder_dl_info_t Dl_info;

#endif

#ifdef __cplusplus
}
#endif
