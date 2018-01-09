#include <stdio.h>
#include "SDL.h"
#include "qu_str.h"
#include "qu_log.h"

void qu_dbg_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

static
void qu_dbg_report_failure(qu_log_level level, const char *what, 
    const char *expr, const char *file, int line, const char *func)
{
    static
    SDL_atomic_t recursion_watchdog = { .value = 0 };
    
    static
    const int recursion_watchdog_treshold = 8;
    
    if (SDL_AtomicAdd(&recursion_watchdog, 1) < recursion_watchdog_treshold)
    {
        qu_log_begin(NULL, level)
        qu_octx_print_str(log_octx, qu_str_null(file));
        qu_octx_print_str(log_octx, ":");
        qu_octx_print_int(log_octx, line); 
        qu_octx_print_str(log_octx, ": ");
        qu_octx_print_str(log_octx, qu_str_null(what));
        qu_octx_print_str(log_octx, "(");
        qu_octx_print_str(log_octx, qu_str_null(expr));
        qu_octx_print_str(log_octx, ") fail at ");
        qu_octx_print_str(log_octx, qu_str_null(func));
        qu_log_end
    }
    else
    {
        qu_dbg_printf(
            "[watchdog] %s:%d: %s(%s) fail at %s\n",
            qu_str_null(file), 
            line, 
            qu_str_null(what), 
            qu_str_null(expr),
            qu_str_null(func));
    }
    
    SDL_AtomicAdd(&recursion_watchdog, -1);
}

void qu_dbg_on_pass_failure(const char *expr,
    const char *file, int line, const char *func)
{
    qu_dbg_report_failure(qu_log_level_error, "qu_pass", 
        expr, file, line, func);
}

void qu_dbg_on_assert_failure(const char *expr,
    const char *file, int line, const char *func)
{
    qu_dbg_report_failure(qu_log_level_critical, "qu_assert", 
        expr, file, line, func);
    abort();
}
