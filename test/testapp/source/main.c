#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <switch.h>
#include <math.h>
#include <solder.h>

static PadState pad;

void wait_for_button(void) {
  printf("\npress PLUS to continue\n\n");
  while (appletMainLoop()) {
    padUpdate(&pad);
    u64 kDown = padGetButtonsDown(&pad);
    if (kDown & HidNpadButton_Plus)
      break;
    consoleUpdate(NULL);
  }
}

int main(int argc, char* argv[]) {
  // init solder as early as possible
  int rc = solder_init(0);

  void *clib = NULL;
  int (*fn_test)(float x) = NULL;
  void *cpplib = NULL;
  int (*fn_test_cpp)(int i, float x) = NULL;
  int (*fn_puts)(const char *) = NULL;

  // init console afterwards in case it allocs
  consoleInit(NULL);
  padConfigureInput(1, HidNpadStyleSet_NpadStandard);
  padInitializeDefault(&pad);

  if (rc != 0) {
    printf("solder error %d: %s\n", rc, solder_dlerror());
    goto _exit;
  }

  printf("opening testlib.so\n");
  clib = solder_dlopen("testlib.so", SOLDER_GLOBAL);
  if (!clib) {
    printf("could not open testlib.so: %s\n", solder_dlerror());
    goto _exit;
  }

  printf("resolving test\n");
  fn_test = (int (*)(float x))solder_dlsym(clib, "test");
  if (!fn_test) {
    printf("could not resolve `test`: %s\n", solder_dlerror());
    goto _exit;
  }

  printf("running fn_test\n");
  rc = fn_test(69.f);
  printf("test() returned %d\n", rc);

  wait_for_button();

  printf("opening testlib_cpp.so\n");
  cpplib = solder_dlopen("testlib_cpp.so", SOLDER_LOCAL | SOLDER_LAZY);
  if (!cpplib) {
    printf("could not open testlib_cpp.so: %s\n", solder_dlerror());
    goto _exit;
  }

  printf("resolving test_cpp (this will also execute init arrays)\n");
  fn_test_cpp = (int (*)(int i, float x))solder_dlsym(cpplib, "test_cpp");
  if (!fn_test_cpp) {
    printf("could not resolve `test_cpp`: %s\n", solder_dlerror());
    goto _exit;
  }

  printf("running test_cpp with good arguments\n");
  rc = fn_test_cpp(0, 5.f);
  printf("test_cpp() returned %d\n", rc);

  wait_for_button();

  printf("running test_cpp with bad arguments\n");
  rc = fn_test_cpp(69, 0.f);
  printf("test_cpp() returned %d\n", rc);

  wait_for_button();

  printf("trying to `dlsym` the main module\n");
  fn_puts = (int (*)(const char *))solder_dlsym(NULL, "puts");
  if (!fn_puts) {
    printf("could not find `puts` in main module: %s\n", solder_dlerror());
    goto _exit;
  }
  fn_puts("I AM PUTS\n");

  wait_for_button();

_exit:
  if (cpplib && solder_dlclose(cpplib))
    printf("could not unload testlib_cpp: %s\n", solder_dlerror());
  if (clib && solder_dlclose(clib))
    printf("could not unload testlib: %s\n", solder_dlerror());
  printf("libs unloaded\n");
  wait_for_button();
  solder_quit();
  consoleExit(NULL);

  return 0;
}
