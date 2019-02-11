
#pragma once

#ifndef LOGGING_H
#define LOGGING_H

#include "dnsserver.h"
#include "spdlog/spdlog.h"

#define WARN spdlog::warn
#define ERROR spdlog::error
#define INFO spdlog::info
#define DEBUG spdlog::debug

namespace logging
{
    using utils::log_level;

    void set_default_level(log_level);

}  // namespace logging

#endif
