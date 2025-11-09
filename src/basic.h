// By Monica Moniot
// This header contains a large set macros I find essential for
// programming in C. Just #include this header file to use it.

#ifndef BASIC__H_INCLUDE
#define BASIC__H_INCLUDE

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef uint8_t  byte;
typedef uint32_t uint;
typedef  int8_t   int8;
typedef uint8_t  uint8;
typedef  int16_t  int16;
typedef uint16_t uint16;
typedef  int32_t  int32;
typedef uint32_t uint32;
typedef  int64_t  int64;
typedef uint64_t uint64;

#if defined(_WIN64) || defined(__x86_64__) || defined(__ia64__) || defined(__LP64__)
#define PTR64
#endif
#ifdef PTR64
typedef char mam__testsize2_ptr[sizeof(char *) == 8];
typedef uint64 uinta;
typedef int64  inta;
#else
typedef char mam__testsize2_ptr[sizeof(char *) == 4];
typedef uint32 uinta;
typedef int32  inta;
#endif

#ifndef alloca
#ifdef _MSC_VER
#include <malloc.h>
#ifndef alloca
#define alloca(size) _alloca(size)
#endif
#else
#include <alloca.h>
#endif
#endif
#define allocat(type, size) ((type *)alloca(sizeof(type) * (size)))

#define MACRO_CAT_(a, b) a##b
#define MACRO_CAT(a, b) MACRO_CAT_(a, b)
#define UNIQUE_NAME(prefix) MACRO_CAT(prefix, __LINE__)

#define KILOBYTE (((inta)1)<<10)
#define MEGABYTE (((inta)1)<<20)
#define GIGABYTE (((inta)1)<<30)
#define TERABYTE (((int64)1)<<40)

#define M_PI 3.14159265358979323846f
#define M_EPS (1.0f / MEGABYTE)
#define MAX_UINT32 0xffffffffu
#define MAX_UINT64 0xffffffffffffffffull
#define MIN_INT32 0x80000000
#define MAX_INT32 0x7fffffff
#define MIN_INT64 0x8000000000000000ll
#define MAX_INT64 0x7fffffffffffffffll

#define degtorad(a) ((a)*(M_PI/180f))
#define radtodeg(a) ((a)*(180f/M_PI))
#define tobyte32(b0, b1, b2, b3) ((((uint32)(b3))<<24) | (((uint32)(b2))<<16) | (((uint32)(b1))<<8) | ((uint32)(b0)))
#define tobyte16(b0, b1) ((((uint16)(b1))<<8) | ((uint16)(b0)))
#define getbyte(bs, i) (((bs)>>((i)<<3)) & 255)
#define getbyte0(bs) ((bs) & 255)
#define getbyte1(bs) (((bs)>>8) & 255)
#define getbyte2(bs) (((bs)>>16) & 255)
#define getbyte3(bs) (((bs)>>24) & 255)

#define cast(type, value) ((type)(value))
#define ptr_add(type, ptr, n) ((type*)((byte*)(ptr) + (n)))
#define ptr_sub(ptr0, ptr1) ((inta)((byte*)(ptr0) - (byte*)(ptr1)))
#define ptr_dist(ptr0, ptr1) abs(ptr_sub(ptr0,ptr1))
#define memzro(ptr, size) memset(ptr, 0, size)
#define memzrot(ptr, size) memset(ptr, 0, sizeof(*ptr) * (size))
#define memcpyt(ptr0, ptr1, size) memcpy(ptr0, ptr1, sizeof(*ptr0)*(size))
#define from_cstr(str) str, strlen(str)
#define swap(type, v0, v1) do {type* mam_t0 = (v0); type* mam_t1 = (v1); type mam_t = *mam_t0; *mam_t0 = *mam_t1; *mam_t1 = mam_t} while(0);
#define malloct(type, size) ((type*)malloc(sizeof(type)*(size)))
#define realloct(type, ptr, size) ((type*)realloc(ptr, sizeof(type)*(size)))
#define memeq(ptr0, size0, ptr1, size1) ((size0) == (size1) && memcmp(ptr0, ptr1, size1) == 0)

#ifndef MAM_NO_FOR
#define for_each_lt(name, size) inta UNIQUE_NAME(name) = (size); for(inta name = 0; name < UNIQUE_NAME(name); name += 1)
#define for_each_lt_rev(name, size) for(inta name = (size) - 1; name >= 0; name -= 1)
#define for_each_in_range(name, r0, r1) inta UNIQUE_NAME(name) = (r1); for(inta name = (r0); name <= UNIQUE_NAME(name); name += 1)
#define for_each_in_range_rev(name, r0, r1) inta UNIQUE_NAME(name) = (r0); for(inta name = (r1); name >= UNIQUE_NAME(name); name -= 1)

#define for_each_in(type, name, array, size) type* UNIQUE_NAME(name) = (array) + (size); for(type* name = (array); name != UNIQUE_NAME(name); name += 1)
#define for_each_in_rev(type, name, array, size) type* UNIQUE_NAME(name) = (array) - 1; for(type* name = (array) + (size) - 1; name != UNIQUE_NAME(name); name -= 1)

#define for_each_idx(type, name, name_ptr, array, size) inta UNIQUE_NAME(name) = (size); type* name_ptr = (array); for(inta name = 0; name < UNIQUE_NAME(name); (name += 1, name_ptr += 1))
#define for_each_idx_rev(type, name, name_ptr, array, size) inta UNIQUE_NAME(name) = (size); type* name_ptr = (array) + UNIQUE_NAME(name) - 1; for(inta name = UNIQUE_NAME(name) - 1; name >= 0; (name -= 1, name_ptr -= 1))
#endif

#endif

    /*
    ------------------------------------------------------------------------------
    This software is available under 2 licenses -- choose whichever you prefer.
    ------------------------------------------------------------------------------
    ALTERNATIVE A - MIT License
    Copyright (c) 2020 Monica Moniot
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
    ------------------------------------------------------------------------------
    ALTERNATIVE B - Public Domain (www.unlicense.org)
    This is free and unencumbered software released into the public domain.
    Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
    software, either in source code form or as a compiled binary, for any purpose,
    commercial or non-commercial, and by any means.
    In jurisdictions that recognize copyright laws, the author or authors of this
    software dedicate any and all copyright interest in the software to the public
    domain. We make this dedication for the benefit of the public at large and to
    the detriment of our heirs and successors. We intend this dedication to be an
    overt act of relinquishment in perpetuity of all present and future rights to
    this software under copyright law.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
    ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    ------------------------------------------------------------------------------
    */
