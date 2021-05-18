#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <switch.h>

#include "util.h"
#include "heap.h"

#define DEFAULT_SO_HEAP_SIZE (32 * 1024 * 1024)

static void *so_heap_base = NULL;
static size_t so_heap_limit = 0;
static void *old_heap_end = NULL;

/* simple heap allocator from vitaGL */

typedef struct h_block_s {
  struct h_block_s *next; // next block in list (either free or allocated)
  uintptr_t base; // block start address
  size_t size; // block size
} h_block_t;

static h_block_t *h_alloclist; // list of allocated blocks
static h_block_t *h_freelist; // list of free blocks

// get new block header
static inline h_block_t *heap_blk_new(void) {
  return calloc(1, sizeof(h_block_t));
}

// release block header
static inline void heap_blk_release(h_block_t *block) {
  free(block);
}

// determine if two blocks can be merged into one
// blocks can only be merged if they're next to each other in memory
static inline int heap_blk_mergeable(h_block_t *a, h_block_t *b) {
  return a->base + a->size == b->base;
}

// inserts a block into the free list and merges with neighboring
// free blocks if possible
static void heap_blk_insert_free(h_block_t *block) {
  h_block_t *curblk = h_freelist;
  h_block_t *prevblk = NULL;
  while (curblk && curblk->base < block->base) {
    prevblk = curblk;
    curblk = curblk->next;
  }

  if (prevblk)
    prevblk->next = block;
  else
    h_freelist = block;

  block->next = curblk;

  if (curblk && heap_blk_mergeable(block, curblk)) {
    block->size += curblk->size;
    block->next = curblk->next;
    heap_blk_release(curblk);
  }

  if (prevblk && heap_blk_mergeable(prevblk, block)) {
    prevblk->size += block->size;
    prevblk->next = block->next;
    heap_blk_release(block);
  }
}

// allocates a block from the heap
// (removes it from free list and adds to alloc list)
static h_block_t *heap_blk_alloc(size_t size, uintptr_t alignment) {
  h_block_t *curblk = h_freelist;
  h_block_t *prevblk = NULL;

  while (curblk) {
    const uint64_t skip = ALIGN_MEM(curblk->base, alignment) - curblk->base;

    if (skip + size <= curblk->size) {
      h_block_t *skipblk = NULL;
      h_block_t *unusedblk = NULL;

      if (skip != 0) {
        skipblk = heap_blk_new();
        if (!skipblk)
          return NULL;
      }

      if (skip + size != curblk->size) {
        unusedblk = heap_blk_new();
        if (!unusedblk) {
          if (skipblk)
            heap_blk_release(skipblk);
          return NULL;
        }
      }

      if (skip != 0) {
        if (prevblk)
          prevblk->next = skipblk;
        else
          h_freelist = skipblk;

        skipblk->next = curblk;
        skipblk->base = curblk->base;
        skipblk->size = skip;

        curblk->base += skip;
        curblk->size -= skip;

        prevblk = skipblk;
      }

      if (size != curblk->size) {
        unusedblk->next = curblk->next;
        curblk->next = unusedblk;
        unusedblk->base = curblk->base + size;
        unusedblk->size = curblk->size - size;
        curblk->size = size;
      }

      if (prevblk)
        prevblk->next = curblk->next;
      else
        h_freelist = curblk->next;

      curblk->next = h_alloclist;
      h_alloclist = curblk;

      return curblk;
    }

    prevblk = curblk;
    curblk = curblk->next;
  }

  return NULL;
}

// frees a previously allocated heap block
// (removes from alloc list and inserts into free list)
static void heap_blk_free(uintptr_t base) {
  h_block_t *curblk = h_alloclist;
  h_block_t *prevblk = NULL;

  while (curblk && curblk->base != base) {
    prevblk = curblk;
    curblk = curblk->next;
  }

  if (!curblk)
    return;

  if (prevblk)
    prevblk->next = curblk->next;
  else
    h_alloclist = curblk->next;

  curblk->next = NULL;

  heap_blk_insert_free(curblk);
}

// initializes heap variables and blockpool
static void heap_init(void) {
  h_alloclist = NULL;
  h_freelist = NULL;
}

// resets heap state and frees allocated block headers
static void heap_destroy(void) {
  h_block_t *n;

  h_block_t *p = h_alloclist;
  while (p) {
    n = p->next;
    heap_blk_release(p);
    p = n;
  }

  p = h_freelist;
  while (p) {
    n = p->next;
    heap_blk_release(p);
    p = n;
  }
}

// adds a memblock to the heap
static void heap_extend(void *base, size_t size) {
  h_block_t *block = heap_blk_new();
  block->next = NULL;
  block->base = (uintptr_t)base;
  block->size = size;
  heap_blk_insert_free(block);
}

// allocates memory from the heap (basically malloc())
void *so_heap_alloc(uint64_t size) {
  h_block_t *block = heap_blk_alloc(size, ALIGN_PAGE);
  return block ? (void *)block->base : NULL;
}

// frees previously allocated heap memory (basically free())
void so_heap_free(void *addr) {
  heap_blk_free((uintptr_t)addr);
}

size_t so_heap_init(int sosize) {
  extern char *fake_heap_start;
  extern char *fake_heap_end;

  if (sosize <= 0)
    sosize = DEFAULT_SO_HEAP_SIZE;

  // leave at least 32MB for the newlib heap
  const intptr_t size = fake_heap_end - fake_heap_start;
  const intptr_t rsize = size - DEFAULT_SO_HEAP_SIZE;
  if (sosize > rsize) {
    set_error("libsolder heap size too large: %d vs max %d", sosize, (int)rsize);
    return 0;
  }

  old_heap_end = fake_heap_end;

  const size_t fake_heap_size = size - sosize;
  fake_heap_end = fake_heap_start + fake_heap_size;

  so_heap_base = (char *)fake_heap_start + fake_heap_size;
  so_heap_base = (void *)ALIGN_MEM((uintptr_t)so_heap_base, ALIGN_PAGE); // align to page size
  so_heap_limit = (char *)fake_heap_start + size - (char *)so_heap_base;

  // initialize our heap
  heap_init();
  heap_extend(so_heap_base, so_heap_limit);

  return so_heap_limit;
}

void so_heap_destroy(void) {
  extern char *fake_heap_end;
  if (so_heap_limit == 0)
    return;
  heap_destroy();
  so_heap_limit = 0;
  so_heap_base = NULL;
  fake_heap_end = old_heap_end;
  old_heap_end = NULL;
}
