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

using string = std::basic_string<CH>;
using istringstream = std::basic_istringstream<CH>;

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

void uvcb_timer_reporter(uv_timer_t *);

void uvcb_server_incoming_alloc(uv_handle_t *, size_t, uv_buf_t *);

void uvcb_server_incoming_recv(
    uv_udp_t *, ssize_t, const uv_buf_t *, const struct sockaddr *, unsigned int);

//utils

namespace utils
{
    template <class T>
    T *str_allocate(size_t count)
    {
        return reinterpret_cast<T *>(::malloc(sizeof(T) * count));
    }


    template <class C>
    size_t strlen(const C *const str)
    {
        return std::char_traits<C>::length(str);
    }

    template <class C>
    int strcmp(const C *const s1, const C *const s2)
    {
        auto sl1 = strlen(s1);
        auto sl2 = strlen(s2);
        return std::char_traits<C>::compare(s1, s2, sl1 > sl2 ? sl2 : sl1);
    }

    template <class C>
    void strcpy(C *to, const C *from)
    {
        std::char_traits<C>::copy(to, from, strlen(from));
    }

    template <class C>
    C *strdup(const C *const str)
    {
        const auto len = strlen(str);
        auto ret = str_allocate<C>(len + 1);
        strcpy(ret, str);
        std::char_traits<C>::assign(ret[len], 0);
        return ret;
    }

    template <class C>
    void strfree(const C *str)
    {
        if (likely(str != nullptr)) {
            ::free((void *)str);
        }
    }

    template <class T>
    T *make(const T *pointer)
    {
        auto ret = ::malloc(sizeof(T));
        memcpy(ret, pointer, sizeof(T));
        return reinterpret_cast<T *>(ret);
    }

    template <class T>
    void destroy(const T *const p)
    {
        if (likely(p != nullptr)) {
            ::free((void *)p);
        }
    }

    void split(std::vector<string> &, const CH *, const CH);

    // config file parser
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

    const CH log_level_prefix[][8] = {"", "ERROR", "WARNING", "INFO", "TRACE"};

}  // namespace utils

namespace hash
{
    class hashtable;
}


#endif
