#include <stdlib.h>
#include <stdio.h>
#include <switch.h>

#include "util.h"
#include "loader.h"
#include "exports.h"
#include "solder.h"

static int init_flags = 0;

int solder_init(const int flags) {
  if (init_flags) {
    set_error("libsolder is already initialized");
    return -1;
  }

  // check that svcSetProcessMemoryPermission and svcMap/UnmapProcessCodeMemory are available
  if (!envIsSyscallHinted(0x73) || !envIsSyscallHinted(0x77) || !envIsSyscallHinted(0x78)) {
    set_error("syscalls not available (0x73, 0x77 or 0x78)");
    return -2;
  }

  // check that we know our own process handle
  if (envGetOwnProcessHandle() == INVALID_HANDLE) {
    set_error("own process handle not available");
    return -3;
  }

  init_flags = SOLDER_INITIALIZED | flags;

  // unless explicitly requested otherwise, try getting symbols from NRO
  if (!(flags & SOLDER_NO_NRO_EXPORTS))
    solder_set_main_exports(NULL, 0);

  solder_dlerror(); // clear error flag

  // unless explicitly requested otherwise, try autoloading all linked libraries
  if (flags & SOLDER_MAIN_AUTOLOAD)
    so_autoload();

  return 0;
}

int solder_init_flags(void) {
  return init_flags;
}

void solder_quit(void) {
  if (!init_flags) {
    set_error("libsolder is not initialized");
    return;
  }

  so_unload_all();

  solder_clear_search_paths();

  init_flags = 0;

  solder_dlerror(); // clear error flag
}
