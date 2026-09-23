/* zlib.h -- hostile fixture: the version macro's closing quote is missing,
   simulating a truncated or corrupted vendored header. Must degrade to "no
   match" (Low confidence), never a crash or an out-of-bounds read. */
#ifndef ZLIB_H
#define ZLIB_H
#define ZLIB_VERSION "1.2.11
#define ZLIB_VERNUM 0x12b0
#endif
