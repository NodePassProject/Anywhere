#ifndef CC_H
#define CC_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

/* --- Types --- */
typedef uint8_t     u8_t;
typedef int8_t      s8_t;
typedef uint16_t    u16_t;
typedef int16_t     s16_t;
typedef uint32_t    u32_t;
typedef int32_t     s32_t;
typedef uintptr_t   mem_ptr_t;

/* --- Byte order: ARM64 iOS is little-endian --- */
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

/* --- Structure packing --- */
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_END
#define PACK_STRUCT_FIELD(x) x

/* --- Platform diagnostics --- */
#define LWIP_PLATFORM_DIAG(x)   do { printf x; } while(0)
#define LWIP_PLATFORM_ASSERT(x) do { printf("Assert \"%s\" failed at line %d in %s\n", \
                                     x, __LINE__, __FILE__); abort(); } while(0)

/* --- Compiler hints --- */
#ifndef LWIP_NO_STDDEF_H
#define LWIP_NO_STDDEF_H 0
#endif

#ifndef LWIP_NO_STDINT_H
#define LWIP_NO_STDINT_H 0
#endif

#ifndef LWIP_NO_INTTYPES_H
#define LWIP_NO_INTTYPES_H 0
#endif

/* --- Random number generation --- */
#define LWIP_RAND() ((u32_t)arc4random())

#endif /* CC_H */
