/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// logging.cpp: log facitity implements

#include "logging.h"

#include <unistd.h>

using namespace logging;

logger* logging::__log = nullptr;

namespace
{
    const int new_stdout_fileno = 99;

#define LEVEL_STRING(__level) \
    case level::__level:      \
        return #__level;

    inline constexpr const char* level_string(level l)
    {
        switch (l) {
            LEVEL_STRING(none)
            LEVEL_STRING(fatal)
            LEVEL_STRING(error)
            LEVEL_STRING(warn)
            LEVEL_STRING(info)
            LEVEL_STRING(debug)
            LEVEL_STRING(trace)
#ifndef NDEBUG
            case level::debug_trace:
                return "dtrac";
#endif
        }
        return "";
    }

#define LEVEL_COLOR(__level, __color) \
    case level::__level:              \
        return __color;

    inline constexpr const char* color_dispatch(level l)
    {
        switch (l) {
            LEVEL_COLOR(none, STYLE_NONE)
            LEVEL_COLOR(fatal, STYLE_FATAL)
            LEVEL_COLOR(error, STYLE_ERROR)
            LEVEL_COLOR(warn, STYLE_WARN)
            LEVEL_COLOR(info, STYLE_INFO)
            LEVEL_COLOR(debug, STYLE_DEBUG)
            LEVEL_COLOR(trace, STYLE_TRACE)
#ifndef NDEBUG
            LEVEL_COLOR(debug_trace, STYLE_DTRACE)
#endif
        }
        return "";
    }
#undef LEVEL_COLOR
#undef LEVEL_STRING

}  // namespace


namespace logging
{
    void destroy_logger()
    {
        __log->stop();
        logger::destroy();
    }


    void set_default_level(log_level ll)
    {
        auto level = ::logging::level::debug;
        switch (ll) {
            case utils::LL_DEBUG:
                level = ::logging::level::debug;
                break;
            case utils::LL_TRACE:
                level = ::logging::level::trace;
                break;
            case utils::LL_ERROR:
                level = ::logging::level::error;
                break;
            case utils::LL_WARNING:
                level = ::logging::level::warn;
                break;
            case utils::LL_INFO:
                level = ::logging::level::info;
                break;
            case utils::LL_OFF:
                level = ::logging::level::none;
                break;
            default:
                level = ::logging::level::info;
                break;
        }
        __log->set_level(level);
    }

    void init_logging()
    {
        logger::init_logger();
        __log->start();
    }

}  // namespace logging


log_sink::log_sink(int fd)
{
    dest = fd;
    istty = isatty(dest) == 1;
    wrote = 0;
}

void log_sink::write(const logging_object& obj)
{
    const char *color, *reset;

    if (istty) {
        color = color_dispatch(obj.l);
        reset = STYLE_RESET;
    } else {
        color = reset = "";
    }

    auto buffer =
        fmt::format("{0} [{1}{2:5}{3}] - {4}\n", obj.t, color, level_string(obj.l), reset, obj.msg);

    auto w = ::write(dest, buffer.c_str(), buffer.length());
    if (w == -1) {
        fatal("writing message failed");
    } else {
        wrote += w;
    }
    if (obj.l == level::fatal) {
        exit(-1);
    }
}

logging_object::logging_object(level lv, string&& message) : msg(message), l(lv) {}

void logger::init_logger()
{
    logging::__log = new logger;
    int stdout = dup2(STDOUT_FILENO, new_stdout_fileno);
    __log->sinks->emplace_back(new_stdout_fileno);
}

void logger::destroy()
{
    delete logging::__log;
}

logger::~logger()
{
    pthread_mutex_destroy(mutex);
    pthread_cond_destroy(cond);
    delete pool;
    delete sinks;
    delete mutex;
    delete cond;
    delete working_thread;
    delete queue;
}

logger::logger()
{
    cond = new pthread_cond_t;
    mutex = new pthread_mutex_t;
    sinks = new std::vector<log_sink>;
    queue = new std::queue<logging_object*>;
    working_thread = new pthread_t;
    pthread_mutex_init(mutex, nullptr);
    logging_level = level::info;
    pthread_cond_init(cond, nullptr);
    pool = new utils::allocator_pool<logging_object>(10);
}

void logger::stop()
{
    pthread_mutex_lock(mutex);
    queue->emplace(nullptr);
    pthread_cond_signal(cond);
    pthread_mutex_unlock(mutex);
    pthread_join(*working_thread, nullptr);
}

void logger::start()
{
    pool->for_each([](logging_object* obj) {
        obj->msg = "";
        obj->msg.reserve(30);
    });
    pthread_create(working_thread, nullptr, logging_thread, nullptr);
}

void logger::set_level(level l)
{
    logging_level = l;
}

void logger::write(level l, string&& msg)
{
    auto lo = new_logging_object(l, std::move(msg));
    pthread_mutex_lock(mutex);
    queue->emplace(lo);
    pthread_cond_signal(cond);
    pthread_mutex_unlock(mutex);
}

void* logging_thread(void*)
{
    static auto instance = logging::__log;
    while (true) {
        pthread_mutex_lock(instance->mutex);
        while (instance->queue->size() == 0) {
            pthread_cond_wait(instance->cond, instance->mutex);
        }
        auto data = instance->queue->front();
        instance->queue->pop();
        if (unlikely(data != nullptr)) {
            for (auto& sink : *instance->sinks) {
                sink.write(*data);
            }
            instance->delete_logging_object(data);
        } else {
            pthread_mutex_unlock(instance->mutex);
            return nullptr;
        }
        pthread_mutex_unlock(instance->mutex);
    }
}
