#pragma once

#include <stdlib.h>

size_t so_heap_init(int sosize);
void so_heap_destroy(void);

void *so_heap_alloc(size_t size);
void so_heap_free(void *addr);
