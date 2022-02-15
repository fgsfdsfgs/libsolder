#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <switch.h>
#include <elf.h>

// internal types and decls

enum dynmod_flags_internal {
  // states
  MOD_RELOCATED   = 1 << 17,
  MOD_MAPPED      = 1 << 18,
  MOD_INITIALIZED = 1 << 19,
  // additional flags
  MOD_OWN_SYMTAB  = 1 << 24,
};

typedef struct dynmod_seg {
  void *base;
  void *virtbase;
  size_t size;
  uint64_t pflags;
} dynmod_seg_t;

typedef struct dynmod {
  char *name;
  int flags;
  int refcount;

  void *load_base;
  void *load_virtbase;
  VirtmemReservation *load_memrv;
  size_t load_size;

  dynmod_seg_t *segs;
  size_t num_segs;

  Elf64_Dyn *dynamic;
  Elf64_Sym *dynsym;
  size_t num_dynsym;

  char *dynstrtab;
  uint32_t *hashtab;

  int (** init_array)(void);
  size_t num_init;

  int (** fini_array)(void);
  size_t num_fini;

  void *readtp_virtbase;
  void *readtp_base;
  size_t readtp_size;

  int tls_offset;
  int tls_size;

  struct dynmod *next;
  struct dynmod *prev;
} dynmod_t;

struct searchpath {
  char *path;
  struct searchpath *next;
};

// some libc stuff we're going to need
extern int _start;
extern const int _DYNAMIC;
extern void *__aarch64_read_tp(void);

// module list; head is always main module
extern dynmod_t solder_dsolist;

// search path list
extern struct searchpath *solder_searchlist;
