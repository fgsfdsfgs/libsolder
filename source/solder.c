#include <stdlib.h>
#include <stdio.h>

#include "util.h"
#include "heap.h"
#include "loader.h"
#include "exports.h"
#include "solder.h"

static int init_flags = 0;

int solder_init(const int heapsize, const int flags) {
  if (init_flags) {
    set_error("libsolder is already initialized");
    return -2;
  }

  const size_t hsize = so_heap_init(heapsize);
  if (hsize == 0) return -1;

  init_flags = SOLDER_INITIALIZED | flags;

  // unless explicitly requested otherwise, try getting symbols from NRO
  if (!(flags & SOLDER_NO_NRO_EXPORTS))
    solder_set_main_exports(NULL, 0);

  solder_dlerror(); // clear error flag

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
  so_heap_destroy();

  init_flags = 0;

  solder_dlerror(); // clear error flag
}
