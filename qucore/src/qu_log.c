#include <stdio.h>

#include "SDL.h"
#include "qu_log.h"

#define qu_log_msg_capacity 128

typedef struct qu_log_msg_
{
    char data[qu_log_msg_capacity];
    char *p;
} qu_log_msg;

typedef struct qu_alarm_octx_
{
    qu_octx base;
    bool init;
    qu_log_msg msg;
    bool lost;
} qu_alarm_octx;

static 
bool qu_log_write_alarm_octx(qu_octx *, const void *, size_t);

static 
void qu_log_close_alarm_octx(qu_octx *);

static
qu_octx_type alarm_octx_type = 
{
    .name = "alarm",
    .write = qu_log_write_alarm_octx,
    .close = qu_log_close_alarm_octx
};

#define qu_logger_name_capacity 32

struct qu_logger_
{
    char name[qu_logger_name_capacity];
    qu_log_level threshold;
};

typedef struct qu_log_octx_
{
    qu_octx base;
    bool open;
    const char *logger_name;
    qu_log_level level;
    qu_log_msg msg;
} qu_log_octx;

static 
bool qu_log_write_octx(qu_octx *, const void *, size_t);

static 
void qu_log_close_octx(qu_octx *);

static
qu_octx_type log_octx_type = 
{
    .name = "log",
    .write = qu_log_write_octx,
    .close = qu_log_close_octx
};

typedef struct qu_log_roll_record_
{
    qu_log_record record;
    char msg_data[qu_log_msg_capacity];
} qu_log_roll_record;

typedef struct qu_log_dbg_handler_ 
{
    qu_log_handler base;
} qu_log_dbg_handler;

static
void qu_log_init_dbg_handler(qu_log_handler *);

static
bool qu_log_write_dbg_handler(qu_log_handler *, const qu_log_record *);

static
bool qu_log_activate_dbg_handler(qu_log_handler *);

static
qu_log_handler_type dbg_handler_type =
{
    .name = "dbg",
    .obj_size = sizeof(qu_log_dbg_handler),
    .unique = true,
    .dbg_proxy = true,
    .init = qu_log_init_dbg_handler,
    .activate = qu_log_activate_dbg_handler,
    .write = qu_log_write_dbg_handler
};

#define qu_log_file_handler_path_capacity   512

typedef struct qu_log_file_handler_
{
    qu_log_handler base;
    char path[qu_log_file_handler_path_capacity];
    bool rewriting;
} qu_log_file_handler;

static
void qu_log_init_file_handler(qu_log_handler *);

static
bool qu_log_write_file_handler(qu_log_handler *, const qu_log_record *);

static
bool qu_log_activate_file_handler(qu_log_handler *);

static
qu_log_handler_type file_handler_type =
{
    .name = "file",
    .obj_size = sizeof(qu_log_file_handler),
    .unique = false,
    .dbg_proxy = false,
    .init = qu_log_init_file_handler,
    .activate = qu_log_activate_file_handler,
    .write = qu_log_write_file_handler
};

#define qu_log_logger_capacity 256

#define qu_log_octx_capacity 64

#define qu_log_roll_capacity 256

#define qu_log_handler_type_capacity 32

#define qu_log_handler_capacity 32

#define qu_log_handler_memory_capacity 8192

typedef struct qu_log_
{
    bool init;
    bool open;
    
    SDL_mutex *mutex;
    
    SDL_atomic_t global_threshold;
    qu_log_level loggers_threshold;
    
    size_t logger_count;
    qu_logger loggers[qu_log_logger_capacity];    
    
    qu_log_octx octxs[qu_log_octx_capacity];    
    
    size_t cur_roll_record;
    qu_log_roll_record roll_records[qu_log_roll_capacity];
    
    size_t handler_type_count;
    const qu_log_handler_type *handler_types[qu_log_handler_type_capacity];
    
    size_t handler_count;
    qu_log_handler *handlers[qu_log_handler_capacity];

    char handler_memory[qu_log_handler_memory_capacity];
    char *handler_memory_p;

    bool dbg_proxy_active;
    bool dbg_proxy_lost;
} qu_log;

static
qu_alarm_octx alarm_octx =
{
    .init = false
};

static 
qu_log log = 
{
    .init = false
};

const char *qu_log_level_to_str(qu_log_level level)
{
    switch(level)
    {
    case qu_log_level_none: return "none";
    case qu_log_level_critical: return "critical";
    case qu_log_level_error: return "error";
    case qu_log_level_warning: return "warning";
    case qu_log_level_info: return "info";
    case qu_log_level_debug: return "debug";
    case qu_log_level_verbose: return "verbose";
    case qu_log_level_all: return "all";
    default: return NULL;
    }
}

static
void qu_log_msg_reset(qu_log_msg *msg)
{
    qu_assert(msg != NULL);
    msg->p = msg->data; 
    *msg->p = 0;
}

static
bool qu_log_msg_is_full(qu_log_msg *msg)
{
    qu_assert(msg != NULL);
    return (msg->p + 1 == msg->data + qu_log_msg_capacity);
}

static
bool qu_log_msg_is_empty(qu_log_msg *msg)
{
    qu_assert(msg != NULL);
    return (msg->p == msg->data);
}

static
bool qu_log_msg_push(qu_log_msg *msg, char c)
{
    qu_assert(msg != NULL);
    
    if (qu_fail(!qu_log_msg_is_full(msg)))
        return false;

    *msg->p++ = (c >= ' ' || c < 0 ? c : '?');
    *msg->p = 0;
    return true;
}

void qu_log_close()
{
    if(!log.init)
        return;
  
    log.open = false;
        
    if (log.mutex != NULL)
        log.mutex = (SDL_DestroyMutex(log.mutex), NULL);
    
    bool has_open_octx = false;
    for (size_t n = 0; !has_open_octx && n != qu_log_octx_capacity; ++n)
        has_open_octx = log.octxs[n].open;
    if (has_open_octx)
        qu_dbg_printf("qu_log_close: (!has_open_octx) fail");
}

bool qu_log_open()
{   
    if (!log.init)
    {
        log.open = false;
        log.mutex = NULL;
        log.init = true;
    }
    
    if (qu_fail(!log.open))
        return false;
    
    log.global_threshold.value = qu_log_level_info;
    
    log.loggers_threshold = qu_log_level_all;
    strcpy(log.loggers[0].name, "dbg");
    log.loggers[0].threshold = qu_log_level_all;
    log.logger_count = 1;
    
    for (size_t n = 0; n != qu_log_octx_capacity; ++n)
    {
        qu_log_octx *octx = log.octxs + n;
        qu_octx_init(&octx->base, &log_octx_type);
        octx->open = false;
    }
    
    log.cur_roll_record = 0;
    for (size_t n = 0; n != qu_log_roll_capacity; ++n)
    {
        qu_log_roll_record *record = log.roll_records + n;
        record->record.msg = record->msg_data;
        *record->msg_data = 0;
    }
    
    log.handler_type_count = 0;
    
    log.handler_count = 0;
    log.handler_memory_p = log.handler_memory;

    log.dbg_proxy_active = false;
    log.dbg_proxy_lost = false;
    alarm_octx.lost = false;
    
    bool okay = true;
    if (okay)
    {
        qu_assert(log.mutex == NULL);
        okay = qu_pass((log.mutex = SDL_CreateMutex()) != NULL);
    }

    if (okay)
    {
        log.open = true;
        okay = qu_pass(qu_log_register_handler_type(&dbg_handler_type)) &&
            qu_pass(qu_log_register_handler_type(&file_handler_type));
    }


    if (!okay)
        qu_log_close();
    
    return okay;
}

bool qu_log_set_global_threshold(qu_log_level level)
{
    qu_assert(log.init && log.open);
     
    if (qu_fail(level >= qu_log_level_none && level <= qu_log_level_all))
        return false;
    
    SDL_AtomicSet(&log.global_threshold, (int)level);
    return true;
}

bool qu_log_set_loggers_threshold(qu_log_level level)
{
    qu_assert(log.init && log.open);
    
    if (qu_fail(level >= qu_log_level_none && level <= qu_log_level_all) ||
        qu_fail(SDL_LockMutex(log.mutex) == 0))
        return false;

    log.loggers_threshold = level;
    
    for (size_t n = 0; n != log.logger_count; ++n)
        log.loggers[n].threshold = level;

    qu_passv(SDL_UnlockMutex(log.mutex) == 0);
    return true;
}

qu_logger *qu_log_get_logger(const char *name)
{
    qu_assert(log.init && log.open);

    if (qu_fail(name != NULL) ||
        qu_fail(strlen(name) < qu_logger_name_capacity) ||
        qu_fail(SDL_LockMutex(log.mutex) == 0))
        return NULL;
    
    qu_logger *logger = NULL;
    for (size_t n = 0; logger == NULL && n != log.logger_count; ++n)
        if (strcmp(name, log.loggers[n].name) == 0)
            logger = log.loggers + n;

    if (logger == NULL)
    {
        if (qu_pass(log.logger_count != qu_log_logger_capacity))
        {
            logger = log.loggers + log.logger_count;
            strcpy(logger->name, name);
            logger->threshold = log.loggers_threshold;
            ++log.logger_count;
        }
    }

    qu_passv(SDL_UnlockMutex(log.mutex) == 0);
    return logger;    
}

bool qu_log_set_logger_threshold(qu_logger *logger, qu_log_level level)
{
    qu_assert(log.init && log.open);
         
    if (qu_fail(logger != NULL) ||
        qu_fail(level >= qu_log_level_none && level <= qu_log_level_all))
        return false;
    
    if (qu_fail(SDL_LockMutex(log.mutex) == 0))
        return false;
    
    logger->threshold = level;

    qu_passv(SDL_UnlockMutex(log.mutex) == 0);
    return true;
}

static
void qu_log_flush_alarm_octx(qu_alarm_octx *octx)
{
    qu_assert(octx == &alarm_octx);
    qu_assert(octx->init);
    
    if (!qu_log_msg_is_empty(&octx->msg))
    {
        qu_dbg_printf("[alarm] %s", octx->msg.data);
        qu_log_msg_reset(&octx->msg);
    }
}

static
qu_octx *qu_log_open_alarm_octx(qu_log_level level)
{
    if (qu_fail(level > qu_log_level_none))
        level = qu_log_level_critical;

    if (qu_fail(level < qu_log_level_all))
        level = qu_log_level_verbose;

    if (!alarm_octx.init)
    {
        qu_octx_init(&alarm_octx.base, &alarm_octx_type);
        qu_log_msg_reset(&alarm_octx.msg);
        alarm_octx.init = true;
        alarm_octx.lost = false;
    }

    if (level > qu_log_level_info)
    {
        if (!alarm_octx.lost)
        {
            qu_dbg_printf("qu_log_open_alarm_octx: message lost");
            alarm_octx.lost = true;
        }
        return NULL;
    } 

    qu_log_flush_alarm_octx(&alarm_octx);    
    return &alarm_octx.base;
}

static 
void qu_log_close_alarm_octx(qu_octx *base)
{
    qu_assert(base->type == &alarm_octx_type);
    
    qu_alarm_octx *octx = (qu_alarm_octx *)base;    
    qu_assert(octx == &alarm_octx);
    qu_assert(octx->init);
    
    qu_log_flush_alarm_octx(octx);        
}

static 
bool qu_log_write_alarm_octx(qu_octx *base, const void *data, size_t size)
{
    qu_assert(base->type == &alarm_octx_type); 
    
    qu_alarm_octx *octx = (qu_alarm_octx *)base;    
    qu_assert(octx == &alarm_octx);
    qu_assert(octx->init);
    
    for (const char *p = (const char *)data; size; --size, ++p)
    {
        if (*p == '\n')
            qu_log_flush_alarm_octx(octx);
        else
        {
            if (qu_log_msg_is_full(&octx->msg))
                qu_log_flush_alarm_octx(octx);
            qu_log_msg_push(&octx->msg, *p);
        }
    }
    
    return true;
}

static
qu_octx *qu_log_open_regular_octx(qu_logger *logger, qu_log_level level)
{
    qu_assert(log.init && log.open);
    
    if (qu_fail(level > qu_log_level_none))
        level = qu_log_level_critical;

    if (qu_fail(level < qu_log_level_all))
        level = qu_log_level_verbose;
    
    if (SDL_AtomicGet(&log.global_threshold) < (int)level)
        return NULL;
    
    if (qu_fail(SDL_LockMutex(log.mutex) == 0))
        return NULL;

    if (logger == NULL)
        logger = log.loggers;    
    
    qu_log_octx *octx = NULL;
    
    if (logger->threshold >= level)
    {
        for (size_t n = 0; octx == NULL && n != qu_log_octx_capacity; ++n)
        {
            if (!log.octxs[n].open)
                octx = log.octxs + n;
        }
        if (octx != NULL)
        {
            octx->logger_name = logger->name;
            octx->level = level;
            qu_log_msg_reset(&octx->msg);
            octx->open = true;
        }
        else
            qu_dbg_printf(
                "qu_log_open_regular_octx: (octx != NULL) fail");
    }
    
    qu_passv(SDL_UnlockMutex(log.mutex) == 0);
    return (octx != NULL ? &octx->base : NULL);
}

static 
void qu_log_flush_octx(qu_log_octx *octx)
{
    qu_assert(log.init && log.open);
    qu_assert(octx != NULL);
    qu_assert(octx->open);
    
    if (!qu_log_msg_is_empty(&octx->msg))
    {
        qu_log_roll_record *record = log.roll_records + log.cur_roll_record;
        
        record->record.logger_name = octx->logger_name;
        record->record.level = octx->level;
        strcpy(record->msg_data, octx->msg.data);
        
        log.cur_roll_record = (log.cur_roll_record + 1) % qu_log_roll_capacity;
        
        qu_log_msg_reset(&octx->msg);

        if (!log.dbg_proxy_active)
        {
            if (record->record.level <= qu_log_level_info)
                qu_dbg_printf("[%s %s] %s",
                    record->record.logger_name,
                    qu_log_level_to_str(record->record.level),
                    record->record.msg);
            else if (!log.dbg_proxy_lost)
            {
                qu_dbg_printf("qu_log_flush_octx: message lost");
                log.dbg_proxy_lost = true;
            }
        }
        
        for (size_t n = 0; n != log.handler_count; ++n)
        {
            qu_log_handler *handler = log.handlers[n];
            
            qu_assert(handler->type->write != NULL);
            
            if (handler->active &&
                handler->threshold >= record->record.level)
            {
                handler->active = qu_pass(handler->type->write(
                    handler, &record->record));
            }
        }
    }
}

static 
void qu_log_close_octx(qu_octx *base)
{
    qu_assert(log.init && log.open);
    qu_assert(base != NULL);
    qu_assert(base->type == &log_octx_type);
    
    qu_log_octx *octx = (qu_log_octx *)base;
    
    if (qu_fail(SDL_LockMutex(log.mutex) == 0))
        return;
    
    if (qu_pass(octx->open))
    {    
        qu_log_flush_octx(octx);
        octx->open = false;
    }
    
    qu_passv(SDL_UnlockMutex(log.mutex) == 0);
}

static 
bool qu_log_write_octx(qu_octx *base, const void *data, size_t size)
{    
    qu_assert(log.init && log.open);
    qu_assert(base->type == &log_octx_type);
    qu_assert(base != NULL);
    
    qu_log_octx *octx = (qu_log_octx *)base;
    if (qu_fail(octx->open))
        return false;
    
    for (const char *p = (const char *)data; size; --size, ++p)
    {
        bool flush = false;
        bool push = false;
        
        if (*p == '\n')
            flush = true;
        else
        {
            flush = qu_log_msg_is_full(&octx->msg);
            push = true;
        }
        
        if (flush)
        {            
            if (qu_pass(SDL_LockMutex(log.mutex) == 0))
            {            
                qu_log_flush_octx(octx);            
                qu_passv(SDL_UnlockMutex(log.mutex) == 0);
            }
            else
                return false;
        }
        
        if (push)
            qu_log_msg_push(&octx->msg, *p);
    }
    
    return true;
}

qu_octx *qu_log_open_octx(qu_logger *logger, qu_log_level level)
{    
    return (log.init && log.open ?
        qu_log_open_regular_octx(logger, level) : 
        qu_log_open_alarm_octx(level));
}

bool qu_log_register_handler_type(const qu_log_handler_type *type)
{
    qu_assert(log.init && log.open);
    
    if (qu_fail(type != NULL) ||
        qu_fail(SDL_LockMutex(log.mutex) == 0))
        return false;
    
    qu_assert(type->name != NULL);
    qu_assert(type->obj_size != 0);
    qu_assert(type->init != NULL);
    qu_assert(type->activate != NULL);
    qu_assert(type->write != NULL);
    
    bool okay = qu_pass(log.handler_type_count != qu_log_handler_type_capacity);

    for (size_t n = 0; okay && n != log.handler_type_count; ++n)
        okay = qu_pass(strcmp(log.handler_types[n]->name, type->name) != 0);

    if (okay)
    {
        log.handler_types[log.handler_type_count] = type;
        ++log.handler_type_count;
    }
    
    qu_passv(SDL_UnlockMutex(log.mutex) == 0);
    return okay;
}

static
const qu_log_handler_type *qu_log_get_handler_type(const char *name)
{
    qu_assert(log.init && log.open);
    
    if (qu_fail(name != NULL))
        return NULL;    
    
    const qu_log_handler_type *type = NULL;    
    for (size_t n = 0; type == NULL && n != log.handler_type_count; ++n)
        if (strcmp(log.handler_types[n]->name, name) == 0)
            type =  log.handler_types[n];

    qu_passv(type != NULL);    
    return type;
}

qu_log_handler *qu_log_create_handler(const char *type_name, const char *name)
{
    qu_assert(log.init && log.open);
    
    if (qu_fail(type_name != NULL) ||
        qu_fail(name != NULL) ||
        qu_fail(strlen(name) < qu_log_handler_name_capacity) ||
        qu_fail(SDL_LockMutex(log.mutex) == 0))
        return NULL;
        
    qu_log_handler *handler = NULL;

    const qu_log_handler_type *type = qu_log_get_handler_type(type_name);

    if (qu_pass(type != NULL))
    {    
        for (size_t n = 0; handler == NULL && n != log.handler_count; ++n)
            if (qu_fail(strcmp(log.handlers[n]->name, name) != 0) ||
                qu_fail(!type->unique || log.handlers[n]->type != type))
                    handler = log.handlers[n];
            
        if (qu_pass(handler == NULL) &&
            qu_pass(log.handler_count != qu_log_handler_capacity))
        {
            qu_assert(type->obj_size != 0);
            size_t aligned_size = (type->obj_size + 31) / 32 * 32;
            
            if (qu_pass(log.handler_memory_p + aligned_size <=
                log.handler_memory + qu_log_handler_memory_capacity))
            {
                handler = (qu_log_handler *)log.handler_memory_p;
                
                handler->type = type;
                strcpy(handler->name, name);
                handler->active = false;
                handler->threshold = qu_log_level_all;
                
                log.handlers[log.handler_count] = handler;
                ++log.handler_count;
                log.handler_memory_p += aligned_size;

                qu_assert(type->init != NULL);
                type->init(handler);
            }
        }
    }
        
    qu_passv(SDL_UnlockMutex(log.mutex) == 0);
    return handler;
}

bool qu_log_set_handler_threshold(qu_log_handler *handler, qu_log_level level)
{
    qu_assert(log.init && log.open);
          
    if (qu_fail(handler != NULL) ||
        qu_fail(level >= qu_log_level_none && level <= qu_log_level_all) ||
        qu_fail(SDL_LockMutex(log.mutex) == 0))
        return false;
    
    handler->threshold = level;
    
    qu_passv(SDL_UnlockMutex(log.mutex) == 0);
    return true;
}

bool qu_log_activate_handler(qu_log_handler *handler)
{
    qu_assert(log.init && log.open);
    
    if (qu_fail(handler != NULL) ||
        qu_fail(SDL_LockMutex(log.mutex) == 0))
        return false;

    qu_assert(handler->type != NULL);
    qu_assert(handler->type->activate != NULL);
    qu_assert(handler->type->write != NULL);
    
    bool okay = true;

    if (!handler->active)
    {
        handler->active = qu_pass(handler->type->activate(handler));
        if (handler->active)
        {
            if (handler->type->dbg_proxy)
                log.dbg_proxy_active = handler->active;
            else
            {
                for (size_t n = 0; 
                    handler->active && n != qu_log_roll_capacity; 
                    ++n)
                {
                    const qu_log_roll_record *record = log.roll_records + 
                        ((log.cur_roll_record + n) % qu_log_roll_capacity);

                    if (*record->record.msg != 0 &&
                        handler->threshold >= record->record.level)
                        handler->active = qu_pass(handler->type->write(
                            handler, &record->record));
                }
            }
        }

        okay = handler->active;
    }
    
    qu_passv(SDL_UnlockMutex(log.mutex) == 0);
    return okay;
}

static
void qu_log_init_dbg_handler(qu_log_handler *base)
{
    qu_assert(base != NULL);
    qu_assert(base->type == &dbg_handler_type);
}

static
bool qu_log_activate_dbg_handler(qu_log_handler *base)
{
    qu_assert(base != NULL);
    qu_assert(base->type == &dbg_handler_type);
    qu_assert(!base->active);

    return true;
}

static
bool qu_log_write_dbg_handler(qu_log_handler *base, 
    const qu_log_record *record)
{
    qu_assert(base != NULL);
    qu_assert(base->type == &dbg_handler_type);
    qu_assert(base->active);
    
    qu_dbg_printf(
        "[%s %s] %s",
        record->logger_name,
        qu_log_level_to_str(record->level),
        record->msg
    );
        
    return true;
}

static
void qu_log_init_file_handler(qu_log_handler *base)
{
    qu_assert(base != NULL);
    qu_assert(base->type == &file_handler_type);
    
    qu_log_file_handler *handler = (qu_log_file_handler *)base;

    *handler->path = 0;
    handler->rewriting = false;
}

static
bool qu_log_activate_file_handler(qu_log_handler *base)
{
    qu_assert(base != NULL);
    qu_assert(base->type == &file_handler_type);
    qu_assert(!base->active);

    qu_log_file_handler *handler = (qu_log_file_handler *)base;
    
    if (qu_fail(*handler->path != 0))
        return false;

    SDL_RWops *rwops = SDL_RWFromFile(handler->path, 
        handler->rewriting ? "wb" : "ab");
    if (qu_fail(rwops != NULL))
        return false;

    return qu_pass(SDL_RWclose(rwops) == 0);
}

static
bool qu_log_write_file_handler(qu_log_handler *base, 
    const qu_log_record *record)
{
    qu_assert(base != NULL);
    qu_assert(base->type == &file_handler_type);
    qu_assert(base->active);

    qu_log_file_handler *handler = (qu_log_file_handler *)base;

    if (qu_fail(*handler->path != 0))
        return false;

    SDL_RWops *rwops = SDL_RWFromFile(handler->path, "ab");
    if (qu_fail(rwops != NULL))
        return false;

    size_t logger_name_len = strlen(record->logger_name);
    const char *level_name = qu_log_level_to_str(record->level);
    size_t level_name_len = strlen(level_name);
    size_t msg_len = strlen(record->msg);

    bool okay = 
        qu_pass(SDL_RWwrite(rwops, "[", 1, 1) == 1) &&
        qu_pass(SDL_RWwrite(rwops, record->logger_name, 1, logger_name_len) == 
            logger_name_len) &&
        qu_pass(SDL_RWwrite(rwops, " ", 1, 1) == 1) &&
        qu_pass(SDL_RWwrite(rwops, level_name, 1, level_name_len) == 
            level_name_len) &&
        qu_pass(SDL_RWwrite(rwops, "] ", 1, 2) == 2) &&
        qu_pass(SDL_RWwrite(rwops, record->msg, 1, msg_len) == 
            msg_len) &&
        qu_pass(SDL_RWwrite(rwops, "\n", 1, 1) == 1);

    return qu_pass(SDL_RWclose(rwops) == 0) && okay;
}

bool qu_log_set_file_handler_path(qu_log_handler *base, const char *path)
{
    qu_assert(log.init && log.open);
    
    if (qu_fail(base != NULL) ||
        qu_fail(base->type == &file_handler_type) ||
        qu_fail(path != NULL) ||
        qu_fail(SDL_LockMutex(log.mutex) == 0))
        return false;

    qu_log_file_handler *handler = (qu_log_file_handler *)base;

    bool okay = 
        qu_pass(!base->active) &&
        qu_pass(strlen(path) < qu_log_file_handler_path_capacity);
    if (okay)
        strcpy(handler->path, path);        

    qu_passv(SDL_UnlockMutex(log.mutex) == 0);
    return okay;
}

bool qu_log_enable_file_handler_rewriting(qu_log_handler *base, bool on)
{
    qu_assert(log.init && log.open);
    
    if (qu_fail(base != NULL) ||
        qu_fail(base->type == &file_handler_type) ||
        qu_fail(SDL_LockMutex(log.mutex) == 0))
        return false;

    qu_log_file_handler *handler = (qu_log_file_handler *)base;

    bool okay = qu_pass(!base->active);
    if (okay)
        handler->rewriting = on;

    qu_passv(SDL_UnlockMutex(log.mutex) == 0);
    return okay;
}
