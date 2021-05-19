#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <SDL2/SDL.h>

#define API_VERSION 777

static void *garbage = NULL;
static SDL_Window *window = NULL;
static SDL_Renderer *ren = NULL;

static struct ri {
  int (*gfx_init)(int, int);
  int (*gfx_dummy)(int);
  int (*gfx_get_size)(int *, int *);
  void (*gfx_print)(const char *);
} ri;

int re_init(void) {
  garbage = malloc(256);
  if (!garbage) {
    ri.gfx_print("could not alloc garbage");
    return 0;
  }

  ri.gfx_dummy(666);

  int w = 0, h = 0;
  if (!ri.gfx_get_size(&w, &h)) {
    ri.gfx_print("could not get size");
    free(garbage); garbage = NULL;
    return 0;
  }

  if (!ri.gfx_init(w, h)) {
    ri.gfx_print("could not gfx init");
    free(garbage); garbage = NULL;
  }

  ri.gfx_print("init done");

  return 1;
}

int re_do_thing(void *win) {
  window = (SDL_Window *)win;

  ri.gfx_print("creating renderer");

  ren = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
  if (!ren) {
    ri.gfx_print("could not create renderer");
    return 0;
  }

  ri.gfx_print("renderer created");

  SDL_SetRenderDrawColor(ren, 255, 0, 0, 255);
  SDL_RenderClear(ren);
  SDL_RenderPresent(ren);

  ri.gfx_print("renderer created");

  return 1;
}

int re_get_flags(void) {
  return SDL_SWSURFACE;
}

int re_clear(void) {
  SDL_SetRenderDrawColor(ren, 255, 255, 255, 255);
  SDL_RenderClear(ren);
  SDL_RenderPresent(ren);
  return 0;
}

int re_free(void) {
  ri.gfx_print("bye");
  SDL_DestroyRenderer(ren); ren = NULL;
  free(garbage); garbage = NULL;
  return 0;
}

static struct re {
  int version;
  int (*init)(void);
  int (*do_thing)(void *);
  int (*get_flags)(void);
  int (*clear)(void);
  int (*free)(void);
} re = {
  API_VERSION,
  re_init,
  re_do_thing,
  re_get_flags,
  re_clear,
  re_free,
};

struct re get_api(struct ri in) {
  ri = in;
  return re;
}
