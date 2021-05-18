#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <wchar.h>
#include <wctype.h>
#include <ctype.h>
#include <locale.h>
#include <pthread.h>
#include <errno.h>
#include <float.h>
#include <sys/stat.h>
#include <assert.h>
#include <elf.h>

#include "solder.h"

uint32_t elf_hash(const uint8_t *name) {
  uint64_t h = 0, g;
  while (*name) {
    h = (h << 4) + *name++;
    if ((g = (h & 0xf0000000)) != 0)
      h ^= g >> 24;
    h &= 0x0fffffff;
  }
  return h;
}

const Elf64_Sym *elf_hashtab_lookup(
  const char *strtab,
  const Elf64_Sym *symtab,
  const uint32_t *hashtab,
  const char *symname
) {
    const uint32_t hash = elf_hash((const uint8_t *)symname);
    const uint32_t nbucket = hashtab[0];
    const uint32_t *bucket = &hashtab[2];
    const uint32_t *chain = &bucket[nbucket];
    const uint32_t bucketidx = hash % nbucket;
    for (uint32_t i = bucket[bucketidx]; i; i = chain[i]) {
      if (!strcmp(symname, strtab + symtab[i].st_name))
        return symtab + i;
    }
    return NULL;
}

int symtab_from_nro(
  Elf64_Sym **out_symtab,
  char **out_strtab,
  uint32_t **out_hashtab
) {
  extern const int _DYNAMIC;
  extern const int _start;

  const uintptr_t base = (uintptr_t)&_start;
  const Elf64_Dyn *dyn = (const void *)&_DYNAMIC;
  Elf64_Sym *symtab = NULL;
  char *strtab = NULL;
  uint32_t *hashtab = NULL;

  if (!out_symtab || !out_strtab || !out_hashtab)
    return -1;

  // find dynsymtab, hashtab and strtab; this requires the NRO to have been built with -rdynamic
  for (; dyn->d_tag != DT_NULL; dyn++) {
    switch (dyn->d_tag) {
      case DT_STRTAB:
        strtab = (char *)(base + dyn->d_un.d_ptr);
        break;
      case DT_SYMTAB:
        symtab = (Elf64_Sym *)(base + dyn->d_un.d_ptr);
        break;
      case DT_HASH:
        hashtab = (uint32_t *)(base + dyn->d_un.d_ptr);
        break;
      default:
        break;
    }
  }

  if (!strtab || !symtab || !hashtab)
    return -2;

  *out_strtab = strtab;
  *out_symtab = symtab;
  *out_hashtab = hashtab;

  return 0;
}

int symtab_from_exports(
  const solder_export_t *exp,
  const int numexp,
  Elf64_Sym **out_symtab,
  char **out_strtab,
  uint32_t **out_hashtab
) {
  extern const int _start;
  const uintptr_t base = (uintptr_t)&_start;
  const uint32_t nchain = numexp + 1; // + NULL symbol
  const uint32_t nbucket = nchain * 2 + 1; // FIXME: is this even right
  char *strtab = NULL;
  Elf64_Sym *symtab = NULL;
  uint32_t *hashtab = NULL;

  if (!exp || !numexp || !out_symtab || !out_strtab || !out_hashtab)
    return -1;

  // bucket array + chain array + two ints for lengths
  hashtab = calloc(nchain + nbucket + 2, sizeof(uint32_t));
  if (!hashtab) goto _error;

  symtab = calloc(nchain, sizeof(Elf64_Sym));
  if (!symtab) goto _error;

  // calculate string table size
  size_t strtabsz = 1; // for undefined symname, "\0"
  for (int i = 0; i < numexp; ++i)
    strtabsz += 1 + strlen(exp[i].name);

  strtab = malloc(strtabsz);
  if (!strtab) goto _error;

  // first entry is an empty string
  size_t strptr = 1;
  strtab[0] = '\0';
  symtab[0].st_name = strptr;
  // the rest are just symbol names packed together
  // fill symtab while we're at it
  for (int i = 0; i < numexp; ++i) {
    const size_t slen = strlen(exp[i].name) + 1;
    memcpy(strtab + strptr, exp[i].name, slen);
    symtab[i + 1].st_name = strptr;
    symtab[i + 1].st_shndx = SHN_ABS; // who fucking knows if this is correct
    symtab[i + 1].st_value = (uintptr_t)exp[i].addr_rx - base;
    strptr += slen;
  }
  // should be filled by now
  assert(strtabsz == strptr);

  hashtab[0] = nbucket;
  hashtab[1] = nchain;
  uint32_t *bucket = &hashtab[2];
  uint32_t *chain = &bucket[nbucket];
  for (int i = 0; i < nbucket; i++)
    bucket[i] = STN_UNDEF;
  for (int i = 0; i < nchain; i++)
    chain[i] = STN_UNDEF;

  // fill hash table
  for (Elf64_Word i = 0; i < nchain; ++i) {
    const char *symname = strtab + symtab[i].st_name;
    const uint32_t h = elf_hash((const uint8_t *)symname);
    const uint32_t n = h % nbucket;
    if (bucket[n] == STN_UNDEF) {
      bucket[n] = i;
    } else {
      Elf64_Word y = bucket[n];
      while (chain[y] != STN_UNDEF)
        y = chain[y];
      chain[y] = i;
    }
  }

  *out_symtab = symtab;
  *out_hashtab = hashtab;
  *out_strtab = strtab;

  return 0;

_error:
  free(hashtab);
  free(symtab);
  free(strtab);
  return -1;
}

/* 
   default export table; this exists both to prevent these symbols from being stripped and to provide
   a default set of exports in case the user decides to use SOLDER_NO_NRO_EXPORTS
   this is the bare minimum necessary to run testlib_cpp with local libstdc++
   if you want to go the "link libstdc++ to main" route, you'll have to provide many C++ exports instead
*/

/* unwinding stuff; not declared anywhere, but we can just declare them as ints */

extern int _Unwind_DeleteException;
extern int _Unwind_GetDataRelBase;
extern int _Unwind_GetIPInfo;
extern int _Unwind_GetLanguageSpecificData;
extern int _Unwind_GetRegionStart;
extern int _Unwind_GetTextRelBase;
extern int _Unwind_RaiseException;
extern int _Unwind_Resume;
extern int _Unwind_Resume_or_Rethrow;
extern int _Unwind_SetGR;
extern int _Unwind_SetIP;

const solder_export_t solder_default_exports[] = {
  SOLDER_EXPORT_SYMBOL(_Unwind_DeleteException),
  SOLDER_EXPORT_SYMBOL(_Unwind_GetDataRelBase),
  SOLDER_EXPORT_SYMBOL(_Unwind_GetIPInfo),
  SOLDER_EXPORT_SYMBOL(_Unwind_GetLanguageSpecificData),
  SOLDER_EXPORT_SYMBOL(_Unwind_GetRegionStart),
  SOLDER_EXPORT_SYMBOL(_Unwind_GetTextRelBase),
  SOLDER_EXPORT_SYMBOL(_Unwind_RaiseException),
  SOLDER_EXPORT_SYMBOL(_Unwind_Resume),
  SOLDER_EXPORT_SYMBOL(_Unwind_Resume_or_Rethrow),
  SOLDER_EXPORT_SYMBOL(_Unwind_SetGR),
  SOLDER_EXPORT_SYMBOL(_Unwind_SetIP),

  SOLDER_EXPORT_SYMBOL(__getreent),
  SOLDER_EXPORT_SYMBOL(__errno),
  SOLDER_EXPORT_SYMBOL(__locale_mb_cur_max),
  SOLDER_EXPORT_SYMBOL(_ctype_),

  SOLDER_EXPORT_SYMBOL(setlocale),
  SOLDER_EXPORT_SYMBOL(abort),
  SOLDER_EXPORT_SYMBOL(atexit),
  SOLDER_EXPORT_SYMBOL(exit),

  SOLDER_EXPORT_SYMBOL(printf),
  SOLDER_EXPORT_SYMBOL(putc),
  SOLDER_EXPORT_SYMBOL(puts),
  SOLDER_EXPORT_SYMBOL(getc),

  SOLDER_EXPORT_SYMBOL(fopen),
  SOLDER_EXPORT_SYMBOL(fclose),
  SOLDER_EXPORT_SYMBOL(fputc),
  SOLDER_EXPORT_SYMBOL(fputwc),
  SOLDER_EXPORT_SYMBOL(fputs),
  SOLDER_EXPORT_SYMBOL(fprintf),
  SOLDER_EXPORT_SYMBOL(fscanf),
  SOLDER_EXPORT_SYMBOL(fread),
  SOLDER_EXPORT_SYMBOL(fwrite),
  SOLDER_EXPORT_SYMBOL(fgets),
  SOLDER_EXPORT_SYMBOL(fgetc),
  SOLDER_EXPORT_SYMBOL(fgetwc),
  SOLDER_EXPORT_SYMBOL(fseek),
  SOLDER_EXPORT_SYMBOL(ftell),
  SOLDER_EXPORT_SYMBOL(fstat),
  SOLDER_EXPORT_SYMBOL(fflush),
  SOLDER_EXPORT_SYMBOL(setvbuf),
  SOLDER_EXPORT_SYMBOL(fdopen),
  SOLDER_EXPORT_SYMBOL(fileno),
  SOLDER_EXPORT_SYMBOL(ungetwc),
  SOLDER_EXPORT_SYMBOL(ungetc),

  SOLDER_EXPORT("getwc", &fgetwc), // getwc is a macro
  SOLDER_EXPORT("putwc", &fputwc), // putwc is a macro

  SOLDER_EXPORT_SYMBOL(open),
  SOLDER_EXPORT_SYMBOL(close),
  SOLDER_EXPORT_SYMBOL(read),
  SOLDER_EXPORT_SYMBOL(write),
  SOLDER_EXPORT_SYMBOL(stat),
  SOLDER_EXPORT_SYMBOL(lstat),

  SOLDER_EXPORT_SYMBOL(malloc),
  SOLDER_EXPORT_SYMBOL(free),
  SOLDER_EXPORT_SYMBOL(calloc),
  SOLDER_EXPORT_SYMBOL(realloc),

  SOLDER_EXPORT_SYMBOL(memcpy),
  SOLDER_EXPORT_SYMBOL(wmemcpy),
  SOLDER_EXPORT_SYMBOL(memmove),
  SOLDER_EXPORT_SYMBOL(wmemmove),
  SOLDER_EXPORT_SYMBOL(memset),
  SOLDER_EXPORT_SYMBOL(wmemset),
  SOLDER_EXPORT_SYMBOL(memcmp),
  SOLDER_EXPORT_SYMBOL(wmemcmp),
  SOLDER_EXPORT_SYMBOL(memchr),
  SOLDER_EXPORT_SYMBOL(wmemchr),

  SOLDER_EXPORT_SYMBOL(sscanf),
  SOLDER_EXPORT_SYMBOL(sprintf),
  SOLDER_EXPORT_SYMBOL(snprintf),
  SOLDER_EXPORT_SYMBOL(vsnprintf),
  SOLDER_EXPORT_SYMBOL(strlen),
  SOLDER_EXPORT_SYMBOL(strcpy),
  SOLDER_EXPORT_SYMBOL(strncpy),
  SOLDER_EXPORT_SYMBOL(strcat),
  SOLDER_EXPORT_SYMBOL(strncat),
  SOLDER_EXPORT_SYMBOL(strcmp),
  SOLDER_EXPORT_SYMBOL(strncmp),
  SOLDER_EXPORT_SYMBOL(strcoll),
  SOLDER_EXPORT_SYMBOL(strerror),
  SOLDER_EXPORT_SYMBOL(strftime),
  SOLDER_EXPORT_SYMBOL(strtod),
  SOLDER_EXPORT_SYMBOL(strtof),
  SOLDER_EXPORT_SYMBOL(strtoul),
  SOLDER_EXPORT_SYMBOL(strxfrm),

  SOLDER_EXPORT_SYMBOL(wcrtomb),
  SOLDER_EXPORT_SYMBOL(wcscoll),
  SOLDER_EXPORT_SYMBOL(wcsftime),
  SOLDER_EXPORT_SYMBOL(wcslen),
  SOLDER_EXPORT_SYMBOL(wcsxfrm),
  SOLDER_EXPORT_SYMBOL(wctob),
  SOLDER_EXPORT_SYMBOL(btowc),
  SOLDER_EXPORT_SYMBOL(wctype),
  SOLDER_EXPORT_SYMBOL(mbrtowc),
  SOLDER_EXPORT_SYMBOL(towupper),
  SOLDER_EXPORT_SYMBOL(towlower),
  SOLDER_EXPORT_SYMBOL(iswctype),

  SOLDER_EXPORT_SYMBOL(rand),
  SOLDER_EXPORT_SYMBOL(srand),

  SOLDER_EXPORT_SYMBOL(pthread_cond_broadcast),
  SOLDER_EXPORT_SYMBOL(pthread_cond_wait),
  SOLDER_EXPORT_SYMBOL(pthread_getspecific),
  SOLDER_EXPORT_SYMBOL(pthread_key_create),
  SOLDER_EXPORT_SYMBOL(pthread_key_delete),
  SOLDER_EXPORT_SYMBOL(pthread_mutex_lock),
  SOLDER_EXPORT_SYMBOL(pthread_mutex_unlock),
  SOLDER_EXPORT_SYMBOL(pthread_once),
  SOLDER_EXPORT_SYMBOL(pthread_setspecific),
};

const int solder_num_default_exports = sizeof(solder_default_exports) / sizeof(*solder_default_exports);
