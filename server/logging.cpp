
#include "logging.h"

#include "fmt/time.h"

#include <unistd.h>

#include <ctime>

using namespace logging;

namespace
{
    const int new_stdout_fileno = 99;

#define LEVEL_STRING(__level) \
    case level::__level:      \
        return #__level;

    inline constexpr char* level_string(level l)
    {
        switch (l) {
            LEVEL_STRING(none)
            LEVEL_STRING(fatal)
            LEVEL_STRING(error)
            LEVEL_STRING(warn)
            LEVEL_STRING(info)
            LEVEL_STRING(debug)
            LEVEL_STRING(trace)
        }
        return "";
    }

#define LEVEL_COLOR(__level, __color) \
    case level::__level:              \
        return __color;

    inline constexpr char* color_dispatch(level l)
    {
        switch (l) {
            LEVEL_COLOR(none, "\e[39m")
            LEVEL_COLOR(fatal, "\e[31m")
            LEVEL_COLOR(error, "\e[31m")
            LEVEL_COLOR(warn, "\e[33m")
            LEVEL_COLOR(info, "\e[32m")
            LEVEL_COLOR(debug, "\e[36m")
            LEVEL_COLOR(trace, "\e[34m")
        }
        return "";
    }
#undef LEVEL_COLOR
#undef LEVEL_STRING

}  // namespace


logger* logger::instance = nullptr;

namespace logging
{
    void destroy_logger()
    {
        logger::get_logger().stop();
        logger::destroy();
    }


    void set_default_level(log_level ll)
    {
        auto level = level::debug;
        switch (ll) {
            case utils::LL_TRACE:
                level = level::debug;
                break;
            case utils::LL_ERROR:
                level = level::error;
                break;
            case utils::LL_WARNING:
                level = level::warn;
                break;
            case utils::LL_INFO:
                level = level::info;
                break;
            case utils::LL_OFF:
                level = level::none;
                break;

            default:
                level = level::info;
                break;
        }
        logger::get_logger().set_level(level);
    }

    void init_logging()
    {
        logger::init_logger();
        logger::get_logger().start();
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
    static string buffer;
    static string time_buffer;
    std::tm* t = nullptr;
#ifdef GETTIMEOFDAY
    t = std::localtime(&obj.t.tv_sec);
#else
    t = std::localtime(&obj.t);
#endif

    time_buffer = fmt::format("{:%Y-%m-%d %H:%M:%S}", *t);

    const char *color, *reset;

    if (istty) {
        color = color_dispatch(obj.l);
        reset = "\e[0m";
    } else {
        color = reset = "";
    }

#ifdef GETTIMEOFDAY
    buffer = fmt::format("{0}:{1} [{2}{3}{4}] - {5}\n",
                         time_buffer,
                         obj.t.tv_usec,
                         color,
                         level_string(obj.l),
                         reset,
                         obj.msg);
#else
    buffer = fmt::format(
        "{0} [{1}{2}{3}] - {4}\n", time_buffer, color, level_string(obj.l), reset, obj.msg);
#endif

    auto w = ::write(dest, buffer.c_str(), buffer.length());
    if (w == -1) {
        fatal("writing message failed");
    } else {
        wrote += w;
    }
}

logging_object::logging_object(level lv, const string& message) : msg(message), l(lv)
{
#ifdef GETTIMEOFDAY
    gettimeofday(&t, nullptr);
#else
    time(&t);
#endif
}

void logger::init_logger()
{
    logger::instance = new logger;
    int stdout = dup2(STDOUT_FILENO, new_stdout_fileno);
    instance->sinks->emplace_back(new_stdout_fileno);
}

void logger::destroy()
{
    delete logger::instance;
}

logger::~logger()
{
    pthread_spin_destroy(queue_lock);
    delete sinks;
    delete queue_lock;
    sem_destroy(sem);
    delete sem;
    delete working_thread;
    delete queue;
}

logger::logger()
{
    queue_lock = new pthread_spinlock_t;
    sinks = new std::vector<log_sink>;
    queue = new std::queue<logging_object*>;
    sem = new sem_t;
    working_thread = new pthread_t;
    pthread_spin_init(queue_lock, PTHREAD_PROCESS_PRIVATE);
    sem_init(sem, PTHREAD_PROCESS_PRIVATE, 0);
    logging_level = level::info;
}

void logger::stop()
{
    pthread_spin_lock(queue_lock);
    queue->emplace(nullptr);
    pthread_spin_unlock(queue_lock);
    sem_post(sem);

    pthread_join(*working_thread, nullptr);
}


void logger::start()
{
    pthread_create(logger::instance->working_thread, nullptr, logging_thread, nullptr);
}

logger& logger::get_logger()
{
    if (unlikely(instance == nullptr)) {
        init_logger();
    }
    return *instance;
}

void logger::set_level(level l)
{
    logging_level = l;
}

void logger::write(level l, const string& msg)
{
    auto lo = new logging_object(l, msg);
    pthread_spin_lock(queue_lock);
    queue->emplace(lo);
    pthread_spin_unlock(queue_lock);
    sem_post(sem);
}

void* logging_thread(void*)
{
    auto& instance = logger::get_logger();
    while (true) {
        sem_wait(instance.sem);
        pthread_spin_lock(instance.queue_lock);
        auto data = instance.queue->front();
        instance.queue->pop();
        pthread_spin_unlock(instance.queue_lock);
        if (unlikely(data != nullptr)) {
            for (auto& sink : *instance.sinks) {
                sink.write(*data);
            }
            delete data;
        } else {
            return nullptr;
        }
    }
}
