#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <switch.h>
#include <math.h>
#define SOLDER_LIBDL_COMPAT
#include <solder.h>
#include <SDL2/SDL.h>

/* 
   this example sort of simulates the relationship between quake2.elf and ref_*.so
   additionaly it demonstrates the "libdl compatibility" macros
*/

#define API_VERSION 777

static SDL_Window *window = NULL;

static struct re {
  int version;
  int (*init)(void);
  int (*do_thing)(void *);
  int (*get_flags)(void);
  int (*clear)(void);
  int (*free)(void);
} re;

static int gfx_init(int width, int height) {
  int flags = re.get_flags();
  printf("flags = %08x\n", (unsigned)flags);

  window = SDL_CreateWindow("ass", 0, 0, width, height, flags);
  if (!window) {
    fprintf(stderr, "window = null (%s)\n", SDL_GetError());
    return 0;
  }

  printf("window created\n");

  if (!re.do_thing(window)) {
    fprintf(stderr, "didn't do thing: %s\n", SDL_GetError());
    return 0;
  }

  printf("thing done\n");

  return 1;
}

static int gfx_dummy(int x) {
  printf("this does nothing: %d\n", x);
  return 1;
}

static int gfx_get_size(int *w, int *h) {
  *w = 1280;
  *h = 720;
  return 1;
}

static void gfx_print(const char *msg) {
  printf("gfx says: %s\n", msg);
}

static struct ri {
  int (*gfx_init)(int, int);
  int (*gfx_dummy)(int);
  int (*gfx_get_size)(int *, int *);
  void (*gfx_printf)(const char *);
} ri = {
  gfx_init,
  gfx_dummy,
  gfx_get_size,
  gfx_print
};

int main(int argc, char* argv[]) {
  socketInitializeDefault();
  nxlinkStdio();
  atexit(socketExit);

  // init solder as early as possible
  int rc = solder_init(0);
  if (rc < 0) {
    fprintf(stderr, "solder dead: %s\n", dlerror());
    return 0;
  }
  atexit(solder_quit);

  if (SDL_Init(SDL_INIT_EVERYTHING) < 0) {
    fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
    return 0;
  }
  atexit(SDL_Quit);

  void *hlib = dlopen("sdltestlib.so", RTLD_LOCAL);
  if (!hlib) {
    fprintf(stderr, "could not load lib: %s\n", dlerror());
    return 0;
  }

  struct re (*get_api)(struct ri x) = dlsym(hlib, "get_api");
  if (!get_api) {
    fprintf(stderr, "dlsym failed: %s\n", dlerror());
    return 0;
  }

  re = get_api(ri);
  if (re.version != API_VERSION) {
    fprintf(stderr, "invalid version\n");
    return 0;
  }


  if (!re.init()) {
    fprintf(stderr, "re->init failed\n");
    return 0;
  }

  re.clear();

  SDL_Delay(5000);

  re.free();

  dlclose(hlib);

  return 0;
}
