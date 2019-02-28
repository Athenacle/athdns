
#pragma once

#ifndef DNSSERVER_H
#define DNSSERVER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>

#include <uv.h>

#include <cinttypes>
#include <string>
#include <vector>

#ifdef _WIN32
using CH = wchar_t;
#define PRE(l) L##l
#else
using CH = char;
#define PRE(l) l
#endif

#if !defined likely || !defined unlikely
#define likely(expression) (expression)
#define unlikely(expression) (expression)
#endif

using string = std::basic_string<CH>;

// record.h
class ip_address;
class record_node;
class record_node_A;

// server.h
class global_server;

// dns.h
namespace dns
{
    class Query;
    class DnsPacket;
    class dns_package_builder;
}  // namespace dns


// global functions
const int default_dns_port = 53;

const size_t recv_buffer_size = 512;

void uvcb_server_incoming_alloc(uv_handle_t *, size_t, uv_buf_t *);

void uvcb_server_incoming_recv(
    uv_udp_t *, ssize_t, const uv_buf_t *, const struct sockaddr *, unsigned int);

//utils

namespace utils
{
    void init_buffer_pool(int);

    char *get_buffer();

    void free_buffer(char *);

    void destroy_buffer();


    void split(std::vector<string> &, const CH *, const CH);

    bool check_ip_address(const CH *, uint32_t &);

    void config_system(int, CH *const[]);


    enum log_level {
        LL_OTHERS = 0,
        LL_ERROR = 1,
        LL_WARNING = 2,
        LL_INFO = 3,
        LL_TRACE = 4,
        LL_OFF = 5
    };

    template <class T, class _>
    class atomic_number;

    class bit_container;


    uint32_t rand_value();

}  // namespace utils


namespace hash
{
    class hashtable;
}

enum forward_type { FT_ALL = 0, FT_RANDOM = 1, FT_SEQUENSE = 2 };

#endif
