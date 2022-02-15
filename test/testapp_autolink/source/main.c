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
  socketInitializeDefault();
  nxlinkStdio();
  atexit(socketExit);

  // init solder as early as possible
  int rc = solder_init(SOLDER_MAIN_AUTOLOAD);

  int (*fn_test)(float x) = NULL;
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

  // solder should load all the libraries and crosslink them by this point,
  // but we still need to resolve symbols manually in the main NRO

  printf("resolving test\n");
  fn_test = (int (*)(float x))solder_dlsym(SOLDER_DEFAULT, "test");
  if (!fn_test) {
    printf("could not resolve `test`: %s\n", solder_dlerror());
    goto _exit;
  }

  printf("running fn_test\n");
  rc = fn_test(69.f);
  printf("test() returned %d\n", rc);

  wait_for_button();

  printf("resolving test_cpp\n");
  fn_test_cpp = (int (*)(int i, float x))solder_dlsym(SOLDER_DEFAULT, "test_cpp");
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
  fn_puts = (int (*)(const char *))solder_dlsym(SOLDER_DEFAULT, "puts");
  if (!fn_puts) {
    printf("could not find `puts` in main module: %s\n", solder_dlerror());
    goto _exit;
  }
  fn_puts("I AM PUTS\n");

  wait_for_button();

_exit:
  solder_quit();
  consoleExit(NULL);

  return 0;
}
