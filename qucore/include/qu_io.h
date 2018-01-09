#if !defined (qu_io_H__)
#define qu_io_H__

#include "qu_common.h"

#if defined (__cplusplus)
extern "C" {
#endif

typedef struct qu_octx_ qu_octx;

bool qu_octx_write(qu_octx *octx, const void *data, size_t data_size);

void qu_octx_close(qu_octx *octx);

bool qu_octx_format_nstr(qu_octx *octx, const char *str, size_t str_len,
    size_t min_width, bool left_align, char fill);

bool qu_octx_format_str(qu_octx *octx, const char *str,
    size_t min_width, bool left_align, char fill);

bool qu_octx_format_int(qu_octx *octx, int v, int base,
    size_t min_width, bool left_align, char fill);

bool qu_octx_format_int32(qu_octx *octx, int32_t v, int base,
    size_t min_width, bool left_align, char fill);

bool qu_octx_format_int64(qu_octx *octx, int64_t v, int base,
    size_t min_width, bool left_align, char fill);

bool qu_octx_format_uint(qu_octx *octx, unsigned int v, int base,
    size_t min_width, bool left_align, char fill);

bool qu_octx_format_uint32(qu_octx *octx, uint32_t v, int base,
    size_t min_width, bool left_align, char fill);

bool qu_octx_format_uint64(qu_octx *octx, uint64_t v, int base,
    size_t min_width, bool left_align, char fill);

bool qu_octx_format_size(qu_octx *octx, size_t v, int base,
    size_t min_width, bool left_align, char fill);

bool qu_octx_format_size_units(qu_octx *octx, size_t v,
    size_t min_width, bool left_align, char fill);

bool qu_octx_print_str(qu_octx *octx, const char *str);

bool qu_octx_print_int(qu_octx *octx, int v);

bool qu_octx_print_int32(qu_octx *octx, int32_t v);

bool qu_octx_print_int64(qu_octx *octx, int64_t v);

bool qu_octx_print_uint(qu_octx *octx, unsigned int v);

bool qu_octx_print_uint32(qu_octx *octx, uint32_t v);

bool qu_octx_print_uint64(qu_octx *octx, uint64_t v);

bool qu_octx_print_size(qu_octx *octx, size_t v);

bool qu_octx_print_size_units(qu_octx *octx, size_t v);

typedef struct qu_octx_type_
{
    const char *name;
    bool (*write)(qu_octx *, const void *, size_t);
    void (*close)(qu_octx *);
} qu_octx_type;

struct qu_octx_
{
    const qu_octx_type *type;
};

void qu_octx_init(qu_octx *octx, const qu_octx_type *type);

#if defined (__cplusplus)
}
#endif

#endif
