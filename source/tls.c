#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "common.h"
#include "solder.h"
#include "lookup.h"
#include "util.h"
#include "tls.h"

// space for the DSOs' TLS will be allocated from the main module's TLS
// this is a massive hack, but dynamically allocating TLS blocks would require us
// to modify threadCreate & co

// overridable TLS buffer to generate additional space in the main module's TLS
__attribute__((weak)) __thread uint8_t __solder_tls_buffer[0x10000];
__attribute__((weak)) uint32_t __solder_tls_buffer_size = sizeof(__solder_tls_buffer);

// TLS block "allocator"
static int tls_start = 0;
static int tls_size = 0;
static int tls_offset = 0;

// generate a patched __aarch64_read_tp since all dynamic modules are built with tls-model=local-exec
// switching to a different model seems to be impossible since it leads to devkitA64's gcc generating
// nice memes like `bl __arch64_read_tp; add x0, x0, x0`
static int tls_generate_readtp(dynmod_t *mod) {
  // one page should be enough
  mod->readtp_base = memalign(ALIGN_PAGE, ALIGN_PAGE);
  if (!mod->readtp_base) {
    solder_set_error("`%s`: Could allocate page for __aarch64_read_tp", mod->name);
    return -1;
  }

  // fill it in
  uint32_t *dst = (uint32_t *)mod->readtp_base;
  dst[0] = 0x180000A9; // 00 ldr w9, #0x14
  dst[1] = 0xD53BD060; // 04 mrs x0, tpidrro_el0
  dst[2] = 0xF940FC00; // 08 ldr x0, [x0, #0x1f8]
  dst[3] = 0x8B090000; // 0C add x0, x0, x9
  dst[4] = 0xD65F03C0; // 10 ret
  dst[5] = (uint32_t)(tls_start + mod->tls_offset);
  dst[6] = 0x00000000; // just in case

  // get a page of virtual address space and immediately map it

  Result rc = 0;
  Handle self = envGetOwnProcessHandle();
  mod->readtp_virtbase = NULL;

  virtmemLock();
  mod->readtp_size = ALIGN_PAGE;
  mod->readtp_virtbase = virtmemFindCodeMemory(mod->readtp_size, ALIGN_PAGE);
  rc = svcMapProcessCodeMemory(self, (u64)mod->readtp_virtbase, (u64)mod->readtp_base, mod->readtp_size);
  if (R_SUCCEEDED(rc))
     rc = svcSetProcessMemoryPermission(self, (u64)mod->readtp_virtbase, mod->readtp_size, Perm_Rx);
  virtmemUnlock();

  if (R_FAILED(rc)) {
    solder_set_error("`%s`: Could not map page for __aarch64_read_tp: %08lx", mod->name, rc);
    svcUnmapProcessCodeMemory(self, (u64)mod->readtp_virtbase, (u64)mod->readtp_base, mod->readtp_size);
    free(mod->readtp_base);
    mod->readtp_base = NULL;
    mod->readtp_virtbase = NULL;
    return -2;
  }

  return 0;
}

static inline void tls_alloc_init(uint8_t *tls_base) {
  tls_start = __solder_tls_buffer - tls_base; // start of allocable space
  tls_size = __solder_tls_buffer_size;
  if (tls_size < 0) tls_size = 0;
  tls_offset = 0;
  DEBUG_PRINTF("tls_alloc_init(): available TLS space: %d bytes, start %d\n", tls_size, tls_start);
}

int solder_tls_alloc(dynmod_t *mod) {
  uint8_t *tls_base = __aarch64_read_tp();

  // if the size is not set, set up our shitty allocator
  if (tls_size == 0)
    tls_alloc_init(tls_base);

  // check if the module has any TLS at all
  uint8_t *mod_tls_start = solder_lookup(mod, "__tls_start");
  uint8_t *mod_tls_end = solder_lookup(mod, "__tls_end");
  const int mod_tls_size = mod_tls_end - mod_tls_start;
  if (!mod_tls_start || !mod_tls_end || mod_tls_size <= 0) {
    DEBUG_PRINTF("`%s`: no TLS\n", mod->name);
    return 0;
  }

  if (tls_size == 0 || tls_offset >= tls_size) {
    solder_set_error("`%s`: Main module has no TLS space", mod->name);
    return -1; // no space left
  }

  uint8_t *mod_tdata_start = solder_lookup(mod, "__tdata_lma");
  uint8_t *mod_tdata_end = solder_lookup(mod, "__tdata_lma_end");
  const int mod_tdata_size = mod_tdata_end - mod_tdata_start;
  const int mod_tls_size_aligned = ALIGN_MEM(mod_tls_size, 16); // align it just in case

  if (tls_offset + mod_tls_size_aligned > tls_size) {
    solder_set_error("`%s`: Not enough space in main module's TLS (%d left, %d needed)", mod->name, tls_offset, mod_tls_size_aligned);
    return -2;
  }

  DEBUG_PRINTF("`%s`: module TLS size: %d total, %d data, offset %d\n", mod->name, mod_tls_size, mod_tdata_size, tls_offset);

  // set up the TLS block
  // TODO: this will return this thread's TLS pointer, so spawning modules from threads will probably explode
  if (!tls_base) {
    DEBUG_PRINTF("`%s`: read_tp returned NULL!\n", mod->name);
    return -3;
  }

  // initialize the block
  uint8_t *dst = tls_base + tls_start + tls_offset;
  const int zero_size = mod_tls_size_aligned - mod_tdata_size;
  if (mod_tdata_size)
    memcpy(dst, mod_tdata_start, mod_tdata_size);
  memset(dst + mod_tdata_size, 0, zero_size);

  // generate a patched version of __aarch64_read_tp that adds the offset to our block
  if (tls_generate_readtp(mod))
    return -4;

  mod->tls_offset = tls_offset;
  mod->tls_size = mod_tls_size_aligned;

  DEBUG_PRINTF("`%s`: base TLS: %p, module TLS: %p\n", mod->name, tls_base, dst);

  tls_offset += mod_tls_size_aligned;

  return 0;
}

void solder_tls_free(dynmod_t *mod) {
  if (mod->tls_size != 0 && mod->tls_offset) {
    DEBUG_PRINTF("`%s`: freeing %d bytes of TLS at offset %d\n", mod->name, mod->tls_size, mod->tls_offset);
    if (mod->tls_offset == tls_offset)
      tls_offset -= mod->tls_size;
    mod->tls_size = 0;
    mod->tls_offset = 0;
  }

  if (mod->readtp_virtbase) {
    svcUnmapProcessCodeMemory(envGetOwnProcessHandle(), (u64)mod->readtp_virtbase, (u64)mod->readtp_base, mod->readtp_size);
    mod->readtp_virtbase = NULL;
  }

  if (mod->readtp_base) {
    free(mod->readtp_base);
    mod->readtp_base = NULL;
  }

  mod->readtp_size = 0;
}
