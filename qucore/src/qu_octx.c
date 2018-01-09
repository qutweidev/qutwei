#include "string.h"
#include "qu_str.h"
#include "qu_io.h"

void qu_octx_init(qu_octx *octx, const qu_octx_type *type)
{
    qu_assert(octx != NULL);
    qu_assert(type != NULL);
    qu_assert(type->name != NULL);
    qu_assert(type->write != NULL);
    qu_assert(type->close != NULL);
    
    octx->type = type;
}

bool qu_octx_write(qu_octx *octx, const void *data, size_t data_size)
{
    if (qu_fail(octx != NULL))
        return false;
        
    qu_assert(octx->type != NULL);
    qu_assert(octx->type->write != NULL);
    
    if (data_size == 0)
        return true;
    
    if (qu_fail(data != NULL))
        return false;
    
    return qu_pass(octx->type->write(octx, data, data_size));
}

void qu_octx_close(qu_octx *octx)
{
    if (qu_pass(octx != NULL))
    {
        qu_assert(octx->type != NULL);
        qu_assert(octx->type->close != NULL);        
    
        octx->type->close(octx);
    }
}

static
bool qu_octx_fill(qu_octx *octx, char fill, size_t n)
{
    qu_assert(octx != NULL);
    for ( ; n != 0 && qu_pass(qu_octx_write(octx, &fill, 1)); --n) {}
    return (n == 0);
}

bool qu_octx_format_nstr(qu_octx *octx, const char *str, size_t str_len,
    size_t min_width, bool left_align, char fill)
{
    if (qu_fail(octx != NULL) ||
        qu_fail(str != NULL))
        return false;

    size_t pad = (min_width > str_len ? min_width - str_len : 0);

    return
        (left_align || qu_pass(qu_octx_fill(octx, fill, pad))) &&
        qu_pass(qu_octx_write(octx, str, str_len)) &&    
        (!left_align || qu_pass(qu_octx_fill(octx, fill, pad)));
}

bool qu_octx_format_str(qu_octx *octx, const char *str,
    size_t min_width, bool left_align, char fill)
{
    if (qu_fail(octx != NULL) ||
        qu_fail(str != NULL))
        return false;

    return qu_pass(qu_octx_format_nstr(octx, str, strlen(str), 
        min_width, left_align, fill));
}

#define qu_octx_format_intX(suffix, type) \
    bool qu_octx_format_##suffix(qu_octx *octx, type v, int base, \
        size_t min_width, bool left_align, char fill) \
    { \
        char buf[128]; \
        size_t str_len = qu_str_from_##suffix(buf, 128, v, base); \
        return \
            qu_pass(str_len != 0) && \
            qu_octx_format_nstr(octx, buf, str_len, \
                min_width, left_align, fill); \
    }

qu_octx_format_intX(int, int)
qu_octx_format_intX(int32, int32_t)
qu_octx_format_intX(int64, int64_t)
qu_octx_format_intX(uint, unsigned int)
qu_octx_format_intX(uint32, uint32_t)
qu_octx_format_intX(uint64, uint64_t)
qu_octx_format_intX(size, size_t)

bool qu_octx_format_size_units(qu_octx *octx, size_t v,
    size_t min_width, bool left_align, char fill)
{
    char buf[128];
    size_t str_len = qu_str_from_size_units(buf, 128, v);
    return
        qu_pass(str_len != 0) &&
        qu_octx_format_nstr(octx, buf, str_len,
            min_width, left_align, fill);
}

bool qu_octx_print_str(qu_octx *octx, const char *str)
{
    return qu_pass(qu_octx_format_str(octx, str, 0, false, 0));
}

#define qu_octx_print_intX(suffix, type) \
    bool qu_octx_print_##suffix(qu_octx *octx, type v) \
    { \
        return qu_pass(qu_octx_format_##suffix(octx, v, 10, 0, false, 0)); \
    }

qu_octx_print_intX(int, int)
qu_octx_print_intX(int32, int32_t)
qu_octx_print_intX(int64, int64_t)
qu_octx_print_intX(uint, unsigned int)
qu_octx_print_intX(uint32, uint32_t)
qu_octx_print_intX(uint64, uint64_t)
qu_octx_print_intX(size, size_t)

bool qu_octx_print_size_units(qu_octx *octx, size_t v)
{
    return qu_pass(qu_octx_format_size_units(octx, v, 0, false, 0));
}
