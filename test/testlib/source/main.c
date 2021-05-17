#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

int test(float x) {
  char *buf = malloc(256);
  if (buf) {
    snprintf(buf, 256, "Hello World! sqrtf(x*x) = %f", sqrtf(x * x));
    printf("%s\n", buf);
    free(buf);
  }
  return 1337;
}

float crosslink_this(const char *str, float x, float y) {
  float len = sqrtf(x * x + y * y);
  printf("The length of vector %s is %f\n", str, len);
  fprintf(stderr, "no errors\n");
  return len;
}
