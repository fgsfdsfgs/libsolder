#include <stdio.h>
#include <string.h>

#include "common.h"
#include "util.h"
#include "loader.h"
#include "exports.h"
#include "solder.h"

static int init_flags = 0;

// the main module is the head and is never unloaded
dynmod_t solder_dsolist = {
  "$main",
  .load_virtbase = (void *)&_start,
  .dynamic = (Elf64_Dyn *)&_DYNAMIC,
  // we're already all done
  .flags = MOD_MAPPED | MOD_RELOCATED | MOD_INITIALIZED,
};

// search path list
struct searchpath *solder_searchlist = NULL;

int solder_init(const int flags) {
  if (init_flags) {
    solder_set_error("libsolder is already initialized");
    return -1;
  }

  // check that svcSetProcessMemoryPermission and svcMap/UnmapProcessCodeMemory are available
  if (!envIsSyscallHinted(0x73) || !envIsSyscallHinted(0x77) || !envIsSyscallHinted(0x78)) {
    solder_set_error("syscalls not available (0x73, 0x77 or 0x78)");
    return -2;
  }

  // check that we know our own process handle
  if (envGetOwnProcessHandle() == INVALID_HANDLE) {
    solder_set_error("own process handle not available");
    return -3;
  }

  init_flags = SOLDER_INITIALIZED | flags;

  // unless explicitly requested otherwise, try getting symbols from NRO
  if (!(flags & SOLDER_NO_NRO_EXPORTS))
    solder_set_main_exports(NULL, 0);

  solder_dlerror(); // clear error flag

  // unless explicitly requested otherwise, try autoloading all linked libraries
  if (flags & SOLDER_MAIN_AUTOLOAD)
    solder_autoload();

  return 0;
}

int solder_init_flags(void) {
  return init_flags;
}

void solder_quit(void) {
  if (!init_flags) {
    solder_set_error("libsolder is not initialized");
    return;
  }

  solder_unload_all();

  solder_clear_search_paths();

  init_flags = 0;

  solder_dlerror(); // clear error flag
}

int solder_add_search_path(const char *path) {
  const size_t pathlen = strlen(path) + 1;
  struct searchpath *p = calloc(1, sizeof(*p) + pathlen);
  if (!p) {
    solder_set_error("Could not allocate memory for search path `%s`", path);
    return -1;
  }

  p->path = (char *)p + sizeof(*p);
  p->next = solder_searchlist;
  solder_searchlist = p;
  memcpy(p->path, path, pathlen);

  return 0;
}

void solder_clear_search_paths(void) {
  struct searchpath *p = solder_searchlist;
  while (p) {
    struct searchpath *next = p->next;
    free(p);
    p = next;
  }
  solder_searchlist = NULL;
}
