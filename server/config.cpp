
#include "config_file.h"
#include "dnsserver.h"
#include "logging.h"
#include "server.h"

#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#ifndef APP_NAME
#define APP_NAME "./a.out"
#endif
#endif

using namespace utils;

namespace
{
    [[noreturn]] void usage()
    {
        std::cerr << "Usage: " PROJECT_NAME << " <config file>.";
        exit(1);
    }

    void register_nameserver(global_server& server, const CH* ip)
    {
        uint32_t ns_address;
        if (check_ip_address(ip, ns_address)) {
            server.add_remote_address(ns_address);
        } else {
            ERROR("invalid IP address in {0} ", ip);
        }
    }

    enum class config_parse_state {
        BEGIN,
        NAMESERVER,
        PARALLEL_QUERY,
        CACHE_COUNT,
        LOG,
        LOG_FILE,
        DEFAULT_TTL,
        TIMEOUT_REQUERY,
        SERVER,
        SERVER_DOMAIN_ACCEPT,
        ACCEPT
    };

    void do_parse_config_file(global_server&, FILE* fp)
    {
        yyin = fp;
        yyparse();
        yylex_destroy();
    }


}  // namespace

void utils::config_system(int argc, CH* const argv[])
{
    auto& server = global_server::get_server();
    if (argc != 2) {
        usage();
    }

    auto cf = argv[1];
    auto status = access(cf, R_OK);
    if (status != 0) {
        ERROR("Open configuration file {0} failed: {1}", cf, strerror(errno));
        exit(-1);
    } else {
        const auto fp = fopen(cf, "r");
        if (fp == nullptr) {
            ERROR("Open configuration file {0} failed", cf);
            exit(-1);
        }
        do_parse_config_file(server, fp);
        fclose(fp);
    }
}


void config_add_static_ip(const char* domain, const char* ip)
{
    uint32_t addr;

    auto valid = check_ip_address(ip, addr);
    if (likely(valid)) {
        global_server::get_server().add_static_ip(string(domain), addr);
        DEBUG("add static IP: {0} -> {1}", domain, ip);
    } else {
        ERROR("Invalid IP address: {0}", ip);
    }
}


void config_add_nameserver(const char* ns)
{
    DEBUG("add nameserver {0}", ns);
    register_nameserver(global_server::get_server(), ns);
}

void config_set_parallel_query(int v)
{
    assert(v == VALUE_ON || v == VALUE_OFF);
    DEBUG("set parallel query {0}", v == VALUE_ON ? "ON" : "OFF");
    global_server::get_server().set_parallel_query(v == VALUE_ON);
}

void config_set_cache_count(int cc)
{
    DEBUG("set cache count {0}", cc);
    global_server::get_server().set_cache_size(cc);
}

void config_set_log_level(int ll)
{
    auto level = utils::LL_OFF;

    switch (ll) {
        case LOG_OFF:
            level = utils::LL_OFF;
            break;

        case LOG_TRACE:
            level = utils::LL_TRACE;
            break;
        case LOG_ERROR:
            level = utils::LL_ERROR;
            break;
        case LOG_WARNING:
            level = utils::LL_WARNING;
            break;
        case LOG_INFO:
            level = utils::LL_INFO;
            break;
        default:
            assert(false);
    }
    DEBUG("set log level to {0}", utils::log_level_prefix[level]);
    global_server::get_server().set_server_log_level(level);
}

void config_set_log_file(const char* f)
{
    DEBUG("set log file {0}", f);
    global_server::get_server().set_log_file(f);
}

void config_set_default_ttl(int ttl)
{
    DEBUG("set default ttl {0}", ttl);
    global_server::get_server().set_default_ttl(ttl);
}

void config_set_requery(int re)
{
    assert(re == VALUE_ON || re == VALUE_OFF);
    DEBUG("set timeout-requery {0}", re == VALUE_ON ? "ON" : "OFF");
    global_server::get_server().set_timeout_requery(re == VALUE_ON);
}

int yyerror(const char* str)
{
    ERROR("parsing configuration file failed: {0}", str);
    return 0;
}

void config_set_report_timeout(int to)
{
    global_server::get_server().set_report_timeout(to);
    DEBUG("set report timeout to {0}", to);
}
