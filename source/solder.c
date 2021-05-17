#include <stdlib.h>
#include <stdio.h>

#include "util.h"
#include "heap.h"
#include "loader.h"
#include "exports.h"
#include "solder.h"

static int initialized = 0;

int solder_init(const int heapsize, const int flags) {
  if (initialized) {
    set_error("libsolder is already initialized");
    return -2;
  }

  const size_t hsize = so_heap_init(heapsize);
  if (hsize == 0) return -1;

  initialized = 1;

  // add default exports to main if needed
  if (flags & SOLDER_INIT_EXPORTS)
    solder_add_main_exports(solder_default_exports, solder_num_default_exports);

  solder_dlerror(); // clear error flag

  return 0;
}

void solder_quit(void) {
  if (!initialized) {
    set_error("libsolder is not initialized");
    return;
  }

  so_unload_all();
  so_heap_destroy();

  initialized = 0;

  solder_dlerror(); // clear error flag
}
