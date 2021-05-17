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

#include "solder.h"

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

/* 
   default export table; used when SOLDER_INIT_EXPORTS is enabled
   this is the bare minimum necessary to run testlib_cpp with local libstdc++
   if you want to go the "link libstdc++ to main" route, you'll have to provide many C++ exports
*/

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
