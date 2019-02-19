
#pragma once

#ifndef LOGGING_H
#define LOGGING_H

#if defined __clang__
#pragma clang diagnostic ignored "-Wextra-semi"
#pragma clang diagnostic ignored "-Wunused-member-function"
#pragma clang diagnostic ignored "-Wswitch-enum"
#pragma clang diagnostic ignored "-Wnewline-eof"
#pragma clang diagnostic ignored "-Wmissing-noreturn"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Weverything"
#endif

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

#if defined __clang__
#pragma clang diagnostic enable "-Weverything"
#endif
#endif
