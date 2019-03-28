/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// objects.cpp: global objects implements

#include "objects.h"
#include "dns.h"
#include "server.h"
#include "utils.h"

using namespace dns;
using namespace objects;

response::response(request* p) : req(p) {}

response::~response()
{
    delete req;
}

void response::set_response(char* base, uint32_t size)
{
    uv_buf_t* buf = global_server::get_server().new_uv_buf_t();
    buf->base = utils::get_buffer();
    buf->len = size;
    memmove(buf->base, base, size);
    response_buffer = buf;
}

// request
request::request(
    const uv_buf_t* buffer, ssize_t size, const sockaddr* addr, uv_udp_t* u, dns::DnsPacket* p)
    : nsize(size), pack(p)
{
    buf = global_server::get_server().new_uv_buf_t();
    buf->len = size;
    buf->base = buffer->base;
    sockaddr* new_sock = new sockaddr;
    memmove(new_sock, addr, sizeof(*addr));
    sock = new_sock;
    udp = u;
}

request::~request()
{
    if (likely(sock != nullptr)) {
        utils::free_buffer(buf->base);
        delete sock;
    }
    delete pack;
    global_server::get_server().delete_uv_buf_t(buf);
}


void forward_response::set_response(char* base, uint32_t size)
{
    response::set_response(base, size);
    *reinterpret_cast<uint16_t*>(response_buffer->base) = htons(origin_id);
}

// forward response
forward_response::~forward_response()
{
    utils::free_buffer(response_buffer->base);
    global_server::get_server().delete_uv_buf_t(response_buffer);
}

// forward_item
