#if !defined (qu_str_H__)
#define qu_str_H__

#include "qu_common.h"

#if defined (__cplusplus)
extern "C" {
#endif

const char *qu_str_null(const char *s);

size_t qu_str_from_int(char *buf, size_t size, int v, int base);

size_t qu_str_from_int32(char *buf, size_t size, int32_t v, int base);

size_t qu_str_from_int64(char *buf, size_t size, int64_t v, int base);

size_t qu_str_from_uint(char *buf, size_t size, unsigned int v, int base);

size_t qu_str_from_uint32(char *buf, size_t size, uint32_t v, int base);

size_t qu_str_from_uint64(char *buf, size_t size, uint64_t v, int base);

size_t qu_str_from_size(char *buf, size_t size, size_t v, int base);

size_t qu_str_from_size_units(char *buf, size_t size, size_t v);

#if defined (__cplusplus)
}
#endif

#endif