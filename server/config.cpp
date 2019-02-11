
#include "config_file.h"
#include "dnsserver.h"
#include "server.h"

#include "glog/logging.h"

using namespace google;

#include <getopt.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
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
        VLOG(INFO) << "Usage: " PROJECT_NAME << " <config file>.";
        exit(1);
    }
    void register_nameserver(global_server& server, const CH* ip)
    {
        uint32_t ns_address;
        if (check_ip_address(ip, ns_address)) {
            server.add_remote_address(ns_address);
        } else {
            DLOG(ERROR) << "invalid IP address in " << ip;
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

#define CHECK_STATE(ns)                                                                  \
    if (state != config_parse_state::BEGIN) {                                            \
        DLOG(ERROR) << "config file error: un-expect token: " << yytext << " near line " \
                    << yylineno;                                                         \
    }                                                                                    \
    state = config_parse_state::ns;                                                      \
    break;

    void do_parse_config_file(global_server& server, FILE* fp)
    {
        yyin                  = fp;
        string current_domain = "";
        auto state            = config_parse_state::BEGIN;
        do {
            auto kw = yylex();
            if (kw == FLEX_EOF) {
                break;
            }
            switch (kw) {
                case KW_NAMESERVER:
                    CHECK_STATE(NAMESERVER);
                case STRING_TEXT:
                    if (state == config_parse_state::LOG_FILE) {
                        server.set_log_file(yytext);
                    } else {
                        DLOG(ERROR) << "useless text '" << yytext << "' in line " << yylineno;
                    }
                    state = config_parse_state::ACCEPT;
                    break;
                case DOMAIN:
                    if (state == config_parse_state::SERVER) {
                        current_domain = (yytext);
                        state          = config_parse_state::SERVER_DOMAIN_ACCEPT;
                    } else {
                        DLOG(ERROR)
                            << "useless domain text '" << yytext << "' in line " << yylineno;
                        state = config_parse_state::ACCEPT;
                    }
                    break;
                case NUMBER:
                    if (state == config_parse_state::DEFAULT_TTL) {
                        int ttl = atoi(yytext);
                        VLOG(INFO) << "set default ttl " << ttl;
                        server.set_default_ttl(ttl);
                        state = config_parse_state::ACCEPT;
                    } else if (state == config_parse_state::CACHE_COUNT) {
                        int ttl = atoi(yytext);
                        VLOG(INFO) << "set cache-size " << yytext;
                        server.set_cache_size(static_cast<size_t>(ttl));
                    }
                    state = config_parse_state::ACCEPT;
                    break;
                case IP:
                    if (state == config_parse_state::NAMESERVER) {
                        register_nameserver(server, yytext);
                        state = config_parse_state::ACCEPT;
                    } else if (state == config_parse_state::SERVER_DOMAIN_ACCEPT) {
                        uint32_t ip;
                        check_ip_address(yytext, ip);
                        VLOG(INFO)
                            << "add static address: " << current_domain.c_str() << "->" << yytext;
                        server.add_static_ip(current_domain, ip);
                        state = config_parse_state::ACCEPT;
                    } else {
                        DLOG(ERROR) << "useless IP '" << yytext << "' in line " << yylineno;
                        state = config_parse_state::ACCEPT;
                    }

                    break;
                case KW_ON:
                    if (state == config_parse_state::PARALLEL_QUERY) {
                        VLOG(INFO) << "parallel-query set to ON";
                        server.set_parallel_query(true);
                    } else if (state == config_parse_state::TIMEOUT_REQUERY) {
                        VLOG(INFO) << "timeout re-query set to ON";
                        server.set_timeout_requery(true);
                    } else {
                        DLOG(ERROR) << "useless directive ON in line " << yylineno;
                    }
                    state = config_parse_state::ACCEPT;
                    break;
                case KW_RE_QUERY:
                    CHECK_STATE(TIMEOUT_REQUERY);
                case KW_OFF:
                    if (state == config_parse_state::LOG) {
                        VLOG(INFO) << "disable log output";
                        server.set_server_log_level(utils::log_level::LL_OFF);
                    } else if (state == config_parse_state::PARALLEL_QUERY) {
                        VLOG(INFO) << "parallel-query set to OFF";
                        server.set_parallel_query(false);
                    } else if (state == config_parse_state::TIMEOUT_REQUERY) {
                        VLOG(INFO) << "timeout-requery set to OFF";
                        server.set_timeout_requery(false);
                    } else {
                        DLOG(ERROR) << "useless directive OFF in line " << yylineno;
                    }
                    state = config_parse_state::ACCEPT;
                    break;
                case KW_PARALLEL_QUERY:
                    CHECK_STATE(PARALLEL_QUERY);
                case KW_CACHE_COUNT:
                    CHECK_STATE(CACHE_COUNT);
                case KW_LOG:
                    CHECK_STATE(LOG);
                case KW_LOG_FILE:
                    CHECK_STATE(LOG_FILE);
                case KW_DEFAULT_TTL:
                    CHECK_STATE(DEFAULT_TTL);
                case KW_SERVER:
                    CHECK_STATE(SERVER);

                case NEWLINE:
                    if (state != config_parse_state::ACCEPT && state != config_parse_state::BEGIN) {
                        DLOG(ERROR) << "Config file error occured. In line: " << yylineno;
                    }
                    state = config_parse_state::BEGIN;
                    break;
            }
        } while (true);
    }


}  // namespace

void utils::config_system(int argc, CH* const argv[])
{
    auto& server = global_server::get_server();
    if (argc != 2) {
        usage();
    }

    auto cf     = argv[1];
    auto status = access(cf, R_OK);
    if (status != 0) {
        DLOG(ERROR) << "Open configuration file " << cf << " failed: " << strerror(errno);
        exit(-1);
    } else {
        const auto fp = fopen(cf, "r");
        if (fp == nullptr) {
            DLOG(ERROR) << "Open configuration file " << cf << " failed.";
            exit(-1);
        }
        do_parse_config_file(server, fp);
        fclose(fp);
        yylex_destroy();
    }
}
