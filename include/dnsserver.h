#pragma once

#ifndef DNSSERVER_H
#define DNSSERVER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>

#include <uv.h>

#include <cinttypes>
#include <iostream>
#include <string>
#include <vector>


#ifdef _WIN32
using CH = wchar_t;
#define PRE(l) L##l
#else
using CH = char;
#define PRE(l) l
#endif

class ip_address;
class global_server;
class lostream;

using string        = std::basic_string<CH>;
using istringstream = std::basic_istringstream<CH>;

//
const int default_dns_port = 53;

void uv_handler_on_alloc(uv_handle_t *, size_t, uv_buf_t *);

void uv_handler_on_recv(
    uv_udp_t *, ssize_t, const uv_buf_t *, const struct sockaddr *, unsigned int);

//utils

#ifdef HAVE_LEX
extern std::istream *lexer_istream;
extern "C" void yylex();
#endif


namespace utils
{
    template <class C>
    int strcmp(const C *const s1, const C *const s2)
    {
        auto sl1 = strlen(s1);
        auto sl2 = strlen(s2);
        return std::char_traits<C>::compare(s1, s2, sl1 > sl2 ? sl2 : sl1);
    }

    template <class C>
    size_t strlen(const C *const str)
    {
        return std::char_traits<C>::length(str);
    }

    template <class C>
    void strcpy(C *to, const C *from)
    {
        std::char_traits<C>::copy(to, from, strlen(from));
    }

    template <class C>
    CH *strdup(const C *const str)
    {
        const auto len = strlen(str);
        auto ret       = new C[len + 1];
        strcpy(ret, str);
        std::char_traits<C>::assign(ret[len], 0);
        return ret;
    }

    template <class C>
    void strfree(const C *str)
    {
        delete[] str;
    }

    void split(std::vector<string> &, const CH *, const CH);

    // config file parser
    bool check_ip_address(const CH *, uint32_t &);

    void config_system(int, CH *const[]);


    enum log_level {
        LL_OTHERS  = 0,
        LL_ERROR   = 1,
        LL_WARNING = 2,
        LL_INFO    = 3,
        LL_TRACE   = 4,
        LL_OFF     = 5
    };

    const CH log_level_prefix[][8] = {"", "ERROR", "WARNING", "INFO", "TRACE"};

    class print_able
    {
    public:
        virtual void to_string(string &) const = 0;

        virtual int suggest_size() const
        {
            return -1;
        }
        virtual ~print_able();
    };

}  // namespace utils


class ip_address : public utils::print_able
{
    uint32_t address_;

public:
    ip_address(const ip_address &ip) : address_(ip.get_address()) {}

    explicit ip_address(uint32_t ip) : address_(ip) {}

    void to_string(string &) const override;

    int suggest_size() const override
    {
        return 20;
    }

    ip_address();

    bool operator==(uint32_t cmp) const
    {
        return address_ == cmp;
    }

    bool operator==(const ip_address &cmp) const
    {
        return address_ == cmp.get_address();
    }


    string &getDottedString() const;

    void getDottedString(string &) const;

    uint32_t get_address() const
    {
        return address_;
    }
};

#endif
