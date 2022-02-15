#pragma once

#include "common.h"

dynmod_t *solder_dso_load(const char *filename, const char *modname);
int solder_dso_unload(dynmod_t *mod);
void solder_unload_all(void);
void solder_autoload(void);
