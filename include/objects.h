
#ifndef OBJECTS_H
#define OBJECTS_H

#include "athdns.h"

#include <arpa/inet.h>

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

        request(const uv_buf_t *, ssize_t, const sockaddr *);
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
}  // namespace objects

#endif
