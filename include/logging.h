/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// logging.h: logging facility header

#ifndef LOGGING_H
#define LOGGING_H

#include "athdns.h"
#include "utils.h"

#include "fmt/core.h"

#ifdef GETTIMEOFDAY
#include <sys/time.h>
#endif

#include <queue>
#include <vector>

#define FATAL logging::fatal
#define ERROR logging::error
#define WARN logging::warn
#define INFO logging::info
#define DEBUG logging::debug
#define TRACE logging::trace

#ifndef NDEBUG
#define DTRACE_OUTPUT
#define DTRACE(format, ...) logging::debug_trace(format, __VA_ARGS__)
#define DDEBUG(format, ...) logging::debug_trace(format, __VA_ARGS__)
#else
#undef DTRACE_OUTPUT
#define DDEBUG(format, ...)
#define DTRACE(format, ...)
#endif

#define BUILD_COLOR(value) "\033[" #value "m"
#define STYLE_RESET BUILD_COLOR(0)
#define STYLE_NONE BUILD_COLOR(39)
#define STYLE_FATAL BUILD_COLOR(1) BUILD_COLOR(31)
#define STYLE_ERROR BUILD_COLOR(31)
#define STYLE_WARN BUILD_COLOR(33)
#define STYLE_INFO BUILD_COLOR(32)
#define STYLE_DEBUG BUILD_COLOR(36)
#define STYLE_TRACE BUILD_COLOR(34)
#define STYLE_DTRACE BUILD_COLOR(96)

void* logging_thread(void*);

namespace logging
{
    using utils::log_level;

    enum class level {
        none = 0,
#ifndef NDEBUG
        debug_trace = 1,
#endif
        fatal = 2,
        error = 3,
        warn = 4,
        info = 5,
        debug = 6,
        trace = 7
    };

    void set_default_level(log_level);

    void init_logging();

    struct logging_object {
        string msg;
        level l;
#ifdef GETTIMEOFDAY
        timeval t;
#else
        time_t t;
#endif
        logging_object(level, string&&);

        logging_object() {}

        operator const char*() const
        {
            return msg.c_str();
        }
    };

    class log_sink
    {
        int dest;
        bool istty;
        ssize_t wrote;

    public:
        void write(const logging_object&);

        log_sink(int);
    };


    class logger
    {
        friend void* ::logging_thread(void*);

        level logging_level;
        pthread_t* working_thread;
        std::vector<log_sink>* sinks;
        std::queue<logging_object*>* queue;

        pthread_cond_t* cond;
        pthread_mutex_t* mutex;

        utils::allocator_pool<logging_object>* pool;

    private:
        logger();
        ~logger();

    public:
        level get_log_level() const
        {
            return logging_level;
        }

        static void init_logger();

        void start();

        void write(level, string&&);

        void set_level(level);

        void stop();

        static void destroy();

        logging_object* new_logging_object(level l, string&& msg)
        {
            return pool->allocate(l, std::move(msg));
        }

        void delete_logging_object(logging_object* obj)
        {
            pool->deallocate(obj);
        }
    };

    void destroy_logger();

    extern logger* __log;

    inline level get_default_level()
    {
        return __log->get_log_level();
    }

#define LOGGING_FUNCTION(__level)                                 \
    template <class... Args>                                      \
    inline void __level(const char* __fmt, const Args&... __args) \
    {                                                             \
        auto worker = __log;                                      \
        auto lv = worker->get_log_level();                        \
        if (level::__level <= lv) {                               \
            string msg = fmt::format(__fmt, __args...);           \
            worker->write(level::__level, std::move(msg));        \
        }                                                         \
    }

    LOGGING_FUNCTION(fatal)

    LOGGING_FUNCTION(error)

    LOGGING_FUNCTION(warn)

    LOGGING_FUNCTION(info)

    LOGGING_FUNCTION(debug)

    LOGGING_FUNCTION(trace)

#ifndef NDEBUG
    LOGGING_FUNCTION(debug_trace)
#endif

#undef LOGGING_FUNCTION

}  // namespace logging

#endif
