#include <string.h>
#include "qu_str.h"

const char *qu_str_null(const char *s)
{
    return (s != NULL ? s : "(NULL)");
}

#define qu_str_from_signed_intX(suffix, type) \
    size_t qu_str_from_##suffix(char *buf, size_t size, type v, int base) \
    { \
        if (qu_fail(buf != NULL) || \
            qu_fail(size != 0) || \
            qu_fail(base > 1 && base < 37)) \
            return 0; \
     \
        int digits[64]; \
        size_t digit_count = 0; \
        int sign = (v < 0 ? -1 : 1); \
     \
        while (true) \
        { \
            qu_assert(digit_count != 64); \
            digits[digit_count++] = (v % base) * sign; \
            v = v / base; \
            if (v == 0) \
                break; \
        } \
     \
        if (qu_fail(size > digit_count + (sign < 0 ? 1 : 0))) \
            return 0; \
     \
        char *p = buf; \
     \
        if (sign < 0) \
            *p++ = '-'; \
     \
        while (digit_count != 0) \
        { \
            int c = digits[--digit_count]; \
            c = (c < 10 ? '0' + c : '7' + c); \
            *p++ = (char)c; \
        } \
     \
        *p = 0; \
        return (p - buf); \
    }

qu_str_from_signed_intX(int, int)
qu_str_from_signed_intX(int32, int32_t)
qu_str_from_signed_intX(int64, int64_t)

#define qu_str_from_unsigned_intX(suffix, type) \
    size_t qu_str_from_##suffix(char *buf, size_t size, type v, int base) \
    { \
        if (qu_fail(buf != NULL) || \
            qu_fail(size != 0) || \
            qu_fail(base > 1 && base < 37)) \
            return false; \
     \
        int digits[64]; \
        size_t digit_count = 0; \
     \
        while (true) \
        { \
            qu_assert(digit_count != 64); \
            digits[digit_count++] = (v % base); \
            v = v / base; \
            if (v == 0) \
                break; \
        } \
     \
        if (qu_fail(size > digit_count)) \
            return false; \
     \
        char *p = buf; \
     \
        while (digit_count != 0) \
        { \
            int c = digits[--digit_count]; \
            c = (c < 10 ? '0' + c : '7' + c); \
            *p++ = (char)c; \
        } \
     \
        *p = 0; \
        return (p - buf); \
    }

qu_str_from_unsigned_intX(uint, unsigned int)
qu_str_from_unsigned_intX(uint32, uint32_t)
qu_str_from_unsigned_intX(uint64, uint64_t)
qu_str_from_unsigned_intX(size, size_t)

size_t qu_str_from_size_units(char *buf, size_t size, size_t v)
{
    if (qu_fail(buf != NULL) ||
        qu_fail(size != 0))
        return 0;

    if (v == 0)
    {
        if (qu_fail(size > 3))
            return 0;

        strcpy(buf, "0 B");
        return 3;
    }

    static 
    const char *units[4] = {"B", "KiB", "MiB", "GiB"};

    static 
    const size_t units_len[4] = {1, 3, 3, 3};

    size_t q[4];
    for (int i = 0; i != 3; ++i)
    {
        q[i] = v & 0x3ff;
        v >>= 10;
    }
    q[3] = v;

    char s[64];
    char *p = buf;

    for (int i = 3; i != -1; --i)
    {
        if (q[i] == 0)
            continue;

        if (p != buf)
        {
            if (qu_fail(size > 1))
                return 0;
            *p++ = ' ';
            --size;
        }

        const char *unit = units[i];
        size_t unit_len = units_len[i];

        size_t s_len = qu_str_from_size(s, 64, q[i], 10);
        if (qu_fail(s_len != 0) ||
            qu_fail(size > s_len + 1 + unit_len))
            return 0;

        strcpy(p, s);
        p += s_len;
        *p++ = ' ';
        strcpy(p, unit);
        p += unit_len;
        size -= (s_len + 1 + unit_len);
    }

    *p = 0;
    return (p - buf);
}

