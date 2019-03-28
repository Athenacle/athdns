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
        request(dns::DnsPacket *p) : pack(p)
        {
            sock = nullptr;
        }

        request(const uv_buf_t *, ssize_t, const sockaddr *, uv_udp_t *, dns::DnsPacket *p);

        ~request();
        void set_forward_id(uint16_t fid)
        {
            *reinterpret_cast<uint16_t *>(buf->base) = htons(fid);
        }
    };

    using request_pointer = std::shared_ptr<request>;

    class response
    {
    protected:
        uv_buf_t *response_buffer;
        request *req;

    public:
        response(request *);

        virtual ~response();

        const request *get_request() const
        {
            return req;
        }

        request *get_request()
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

        virtual void set_response(char *, uint32_t);
    };

    class forward_response : public response
    {
        uint16_t forward_id;
        uint16_t origin_id;

    public:
        uint16_t get_original_id() const
        {
            return origin_id;
        }

        forward_response(request *req) : response(req)
        {
            origin_id = htons(*reinterpret_cast<uint16_t *>(req->buf->base));
        }

        void set_forward_id(uint16_t fid)
        {
            forward_id = fid;
            req->set_forward_id(fid);
        }

        uint16_t get_forward_id() const
        {
            return forward_id;
        }

        virtual ~forward_response();

        virtual void set_response(char *, uint32_t) override;
    };

}  // namespace objects

#endif
