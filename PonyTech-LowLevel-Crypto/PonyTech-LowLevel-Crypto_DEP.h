#ifndef __PonyTech_LowLevel_Crypto_LowLevel_Crypto_DEP_h__
#define __PonyTech_LowLevel_Crypto_LowLevel_Crypto_DEP_h__


// General
#include <PonyTech-LowLevel-Basic/memory.h>
#include <string.h>

// Posix
#if defined PLATFORM_DARWIN || defined PLATFORM_LINUX

#endif


// platform specific
#if defined PLATFORM_DARWIN 

#elif defined PLATFORM_LINUX

#else

#endif

#define STATIC_ASSERT_ACT(COND,MSG) typedef char ___static_assertion_##MSG[(COND)? 1 : -1]

// token pasting madness:
#define STATIC_ASSERT_2(COND,MSG) STATIC_ASSERT_ACT(COND,MSG)
#define STATIC_ASSERT_1(COND,MSG) STATIC_ASSERT_2(COND,MSG)
#define STATIC_ASSERT(COND,MSG)  STATIC_ASSERT_1(COND,MSG)

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define ALIGN_WITH(s,a) (((uint32_t)((s) + (a) -1)) & (~(((uint32_t)(a))-1)))




#endif // __PonyTech_LowLevel_Basic_LowLevel_Basic_DEP_h__