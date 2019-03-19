/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// objects.h: system server objects

#ifndef OBJECTS_H
#define OBJECTS_H

#include "athdns.h"

#include "fmt/ostream.h"

#include <arpa/inet.h>
#include <ctime>
#include <memory>

namespace objects
{
    struct send_object {
        const sockaddr *sock;
        uv_buf_t *bufs;
        int bufs_count;
    };

    struct request {
        uv_buf_t *buf;
        ssize_t nsize;
        const sockaddr *sock;
        dns::DnsPacket *pack;
        uv_udp_t *udp;

        request(const uv_buf_t *, ssize_t, const sockaddr *, uv_udp_t *);
        request(dns::DnsPacket *);

        ~request();
    };

    using request_pointer = std::shared_ptr<request>;

    class response
    {
        request_pointer req;

    protected:
        uv_buf_t *response_buffer;

    public:
        response(const request_pointer &);

        virtual ~response();

        const request_pointer &get_request() const
        {
            return req;
        }

        uv_buf_t *get_buffer() const
        {
            return response_buffer;
        }

        const sockaddr *get_sock() const
        {
            return req->sock;
        }
    };

    class found_response : public response
    {
        dns::DnsPacket *packet;

    public:
        found_response(dns::DnsPacket *, const request_pointer &);

        virtual ~found_response();
    };

    struct forward_item {
        request_pointer req;

        dns::DnsPacket *pack;

        uint16_t forward_id;
        uint16_t origin_id;
        pthread_spinlock_t _lock;

        bool response_send;

        void lock()
        {
            pthread_spin_lock(&_lock);
        }

        void unlock()
        {
            pthread_spin_unlock(&_lock);
        }


        void set_response_send()
        {
            pthread_spin_lock(&_lock);
            response_send = true;
            pthread_spin_unlock(&_lock);
        }

        bool get_response_send()
        {
            pthread_spin_lock(&_lock);
            auto rs = response_send;
            pthread_spin_unlock(&_lock);
            return rs;
        }

        forward_item(dns::DnsPacket *, const request_pointer &);

        ~forward_item();
    };

    using forward_item_pointer = std::shared_ptr<forward_item>;

    struct forward_response : public response {
        forward_item_pointer pointer;

        forward_response(forward_item_pointer &item, uv_buf_t *b)
            : response(item->req), pointer(item)
        {
            uint16_t *p = reinterpret_cast<uint16_t *>(b->base);
            *p = item->origin_id;
            response_buffer = b;
        }

        virtual ~forward_response();
    };

    struct forward_queue_item {
        forward_item_pointer item;
        int ns_index;
    };

#ifdef CLOCK_REALTIME_COARSE
#define ATHDNS_CLOCK_GETTIME_FLAG CLOCK_REALTIME_COARSE
#else
#define ATHDNS_CLOCK_GETTIME_FLAG CLOCK_REALTIME
#endif

    class time_object
    {
    public:
        struct timespec t;

        time_object();

        ~time_object() {}

        time_object(const time_object &);

        void operator()();

        static uint64_t diff_to_ns(const time_object &, const time_object &);

        static double diff_to_us(const time_object &, const time_object &);

        static double diff_to_ms(const time_object &, const time_object &);

        time_object &operator=(time_object &&);

        bool operator==(const time_object &) const;
    };
}  // namespace objects

namespace fmt
{
    template <>
    struct formatter<objects::time_object> {
        template <class PC>
        constexpr auto parse(PC &ctx)
        {
            return ctx.begin();
        }

        template <class T>
        auto format(const objects::time_object &__t, T &ctx)
        {
            auto time_buffer = fmt::format("{:%Y-%m-%d %H:%M:%S}", __t.t.tv_sec);
            return format_to(ctx.begin(), "{0}:{1:=06d}", time_buffer, __t.t.tv_nsec);
        }
    };
}  // namespace fmt

#endif
