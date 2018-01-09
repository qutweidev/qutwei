#if !defined (qu_common_H__)
#define qu_common_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "qu_config.h"

#if defined (__cplusplus)
extern "C" {
#endif

void qu_dbg_printf(const char *fmt, ...);

#if defined (qu_pass_on) && defined (qu_pass_off)
    #error qu_pass_* flag conflict
#elif !defined (qu_pass_on) && !defined (qu_pass_off)
    #define qu_pass_on
#endif

#if defined (qu_pass_on)
    void qu_dbg_on_pass_failure(const char *expr,
        const char *file, int line, const char *func);
    
    #define qu_pass(x) ((x) ? true : (qu_dbg_on_pass_failure( \
        #x, __FILE__, __LINE__, __func__), false))
#else
    #define qu_pass(x) (x)
#endif

#define qu_fail(x) (!qu_pass(x))

#define qu_passv(x) ((void)qu_pass(x))

#if defined (qu_assert_on) && defined (qu_assert_off)
    #error qu_assert_* flag conflict
#elif !defined (qu_assert_on) && !defined (qu_assert_off)
    #define qu_assert_on
#endif

#if defined (qu_assert_on)
    void qu_dbg_on_assert_failure(const char *expr,
        const char *file, int line, const char *func);
        
    #define qu_assert(x) { if (!(x)) qu_dbg_on_assert_failure( \
        #x, __FILE__, __LINE__, __func__); }
#else
    #define qu_assert(x) { ((void)0); }
#endif

#if defined (__cplusplus)
}
#endif

#endif
