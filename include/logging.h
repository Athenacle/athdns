
#pragma once

#ifndef LOGGING_H
#define LOGGING_H

#include "dnsserver.h"
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
#define DDEBUG(format, ...) logging::debug(format, __VA_ARGS__)
#else
#define DDEBUG(format, ...) ;
#endif

void* logging_thread(void*);

namespace logging
{
    using utils::log_level;

    enum class level { none = 0, fatal = 1, error = 2, warn = 3, info = 4, debug = 5, trace = 6 };

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
        logging_object(level, const string&);

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
        sem_t* sem;
        std::queue<logging_object*>* queue;
        pthread_spinlock_t* sink_lock;
        pthread_spinlock_t* queue_lock;

    private:
        logger();
        ~logger();

        static logger* instance;

    public:
        level get_log_level() const
        {
            return logging_level;
        }

        static logger& get_logger();

        static void init_logger();

        void start();

        void write(level, const string&);

        void set_level(level);

        void stop();

        static void destroy();
    };

    void destroy_logger();


    inline level get_default_level()
    {
        return logger::get_logger().get_log_level();
    }

#define LOGGING_FUNCTION(__level)                                      \
    template <class... Args>                                           \
    void __level(const char* __fmt, const Args&... __args)             \
    {                                                                  \
        if (level::__level <= logger ::get_logger().get_log_level()) { \
            string msg = fmt::format(__fmt, __args...);                \
            logger::get_logger().write(level::__level, msg);           \
        }                                                              \
    }

    LOGGING_FUNCTION(fatal)

    LOGGING_FUNCTION(error)

    LOGGING_FUNCTION(warn)

    LOGGING_FUNCTION(info)

    LOGGING_FUNCTION(debug)

    LOGGING_FUNCTION(trace)

#undef LOGGING_FUNCTION

}  // namespace logging

#endif
