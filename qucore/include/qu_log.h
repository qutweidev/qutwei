#if !defined (qu_log_H__)
#define qu_log_H__

#include "qu_io.h"

#if defined (__cplusplus)
extern "C" {
#endif

typedef enum qu_log_level_
{
    qu_log_level_none,
    qu_log_level_critical,
    qu_log_level_error,
    qu_log_level_warning,
    qu_log_level_info,
    qu_log_level_debug,
    qu_log_level_verbose,
    qu_log_level_all
} qu_log_level;

typedef struct qu_logger_ qu_logger;

typedef struct qu_log_handler_ qu_log_handler;

typedef struct qu_log_record_
{
    const char *logger_name;
    qu_log_level level;
    const char *msg;
} qu_log_record;

typedef struct qu_log_handler_type_
{
    const char *name;
    size_t obj_size;
    bool unique;
    bool dbg_proxy;
    void (*init)(qu_log_handler *);
    bool (*activate)(qu_log_handler *);
    bool (*write)(qu_log_handler *, const qu_log_record *);
} qu_log_handler_type;

#define qu_log_handler_name_capacity    32

struct qu_log_handler_
{
    const qu_log_handler_type *type;
    char name[qu_log_handler_name_capacity];
    bool active;
    qu_log_level threshold;
};

const char *qu_log_level_to_str(qu_log_level level);

bool qu_log_set_global_threshold(qu_log_level level);

bool qu_log_set_loggers_threshold(qu_log_level level);

qu_logger *qu_log_get_logger(const char *name);

bool qu_log_set_logger_threshold(qu_logger *logger, qu_log_level level);

qu_octx *qu_log_open_octx(qu_logger *logger, qu_log_level level);

qu_log_handler *qu_log_get_handler(const char *name);

bool qu_log_set_handler_threshold(qu_log_handler *, qu_log_level level);

#define qu_log_begin(logger, level) \
    { \
        qu_octx *log_octx = qu_log_open_octx(logger, level); \
        if (log_octx != NULL) \
        {

#define qu_log_end \
            qu_octx_close(log_octx); \
        } \
    }

bool qu_log_register_handler_type(const qu_log_handler_type *type);

qu_log_handler *qu_log_create_handler(const char *type_name, const char *name);

bool qu_log_activate_handler(qu_log_handler *handler);

bool qu_log_set_file_handler_path(qu_log_handler *base, const char *path);

bool qu_log_enable_file_handler_rewriting(qu_log_handler *base, bool on);

#if defined (__cplusplus)
}
#endif

#endif
