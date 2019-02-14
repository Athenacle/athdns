
#pragma once

#ifndef LOGGING_H
#define LOGGING_H

#include "dnsserver.h"
#include "spdlog/spdlog.h"

#define WARN spdlog::warn
#define ERROR spdlog::error
#define INFO spdlog::info
#define DEBUG spdlog::debug

#ifndef NDEBUG
#define DDEBUG(format, ...) spdlog::debug(format, __VA_ARGS__)
#else
#define DDEBUG(format, ...) ;
#endif

namespace logging
{
    using utils::log_level;

    void set_default_level(log_level);

    void init_logging();


}  // namespace logging

#endif
