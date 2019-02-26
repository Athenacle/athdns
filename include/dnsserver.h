#pragma once

#ifndef DNSSERVER_H
#define DNSSERVER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#include <unistd.h>

#include <uv.h>

#include <cinttypes>
#include <cstring>
#include <string>
#include <type_traits>
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

const size_t recv_buffer_size = 512;

void uvcb_timer_reporter(uv_timer_t *);

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

    template <class T, class _ = std::enable_if_t<std::is_integral<T>::value, int>>
    class atomic_number
    {
    private:
        T value;
        pthread_spinlock_t lock;

    public:
        ~atomic_number() {}

        explicit atomic_number(T v = 0) : lock()
        {
            pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE);
            value = v;
        }

        T get()
        {
            pthread_spin_lock(&lock);
            auto ret = value;
            pthread_spin_unlock(&lock);
            return ret;
        }

        T reset(T v)
        {
            pthread_spin_lock(&lock);
            value = v;
            pthread_spin_unlock(&lock);
            return v;
        }

        operator T()
        {
            return get();
        }

        T operator--()
        {
            pthread_spin_lock(&lock);
            value -= 1;
            auto ret = value;
            pthread_spin_unlock(&lock);
            return ret;
        }

        T operator--(int)
        {
            pthread_spin_lock(&lock);
            auto ret = value;
            value -= 1;
            pthread_spin_unlock(&lock);
            return ret;
        }

        T operator++()
        {
            pthread_spin_lock(&lock);
            value += 1;
            auto ret = value;
            pthread_spin_unlock(&lock);
            return ret;
        }

        T operator++(int)
        {
            pthread_spin_lock(&lock);
            auto ret = value;
            value += 1;
            pthread_spin_unlock(&lock);
            return ret;
        }

        T operator=(T v)
        {
            return v;
        }
    };

    using atomic_int = atomic_number<int>;
    using atomic_uint16 = atomic_number<uint16_t>;

    uint32_t rand_value();

    class bit_container
    {
        size_t bc_size;
        size_t buffer_size;
        uint32_t *buffer;

    public:
        size_t size() const
        {
            return bc_size;
        }

        bit_container(size_t total)
        {
            bc_size = total;
            buffer_size = bc_size + 32;
            buffer = new uint32_t[buffer_size / 32];
            memset(buffer, 0, buffer_size / 32);
        }
        ~bit_container()
        {
            delete[] buffer;
        }

        void set(size_t offset, bool value)
        {
            size_t int_offset = offset / 32;
            size_t bit_offset = offset % 32;
            uint32_t mask = 1 << bit_offset;
            if (value) {
                // set to 1
                *(buffer + int_offset) = *(buffer + int_offset) | mask;
            } else {
                mask = ~mask;
                *(buffer + int_offset) &= mask;
            }
        }

        bool test(size_t offset) const
        {
            size_t int_offset = offset / 32;
            size_t bit_offset = offset % 32;
            uint32_t v = *(buffer + int_offset) >> bit_offset;
            return (v & 1) == 1;
        }

        void resize(size_t new_size)
        {
            if (new_size < bc_size) {
                return;
            }
            auto old_buffer_size = buffer_size;
            bc_size = new_size;
            buffer_size = bc_size + 32;
            auto old_buffer = buffer;
            buffer = new uint32_t[buffer_size / 32];
            memset(buffer, 0, buffer_size / 32);
            memcpy(buffer, old_buffer, old_buffer_size / 32);
            delete[] old_buffer;
        }
    };
}  // namespace utils

namespace hash
{
    class hashtable;
}

enum forward_type { FT_ALL = 0, FT_RANDOM = 1, FT_SEQUENSE = 2 };

#endif
