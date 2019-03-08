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

found_response::found_response(DnsPacket* pack, const request_pointer& rq)
    : response(rq), packet(pack)
{
    response_buffer = global_server::get_server().new_uv_buf_t();
    response_buffer->base = reinterpret_cast<char*>(pack->get_data());
    response_buffer->len = pack->get_size();
}

found_response::~found_response()
{
    delete packet;
    global_server::get_server().delete_uv_buf_t(response_buffer);
}

// response
response::response(const request_pointer& p) : req(p) {}

response::~response() {}

// request
request::request(dns::DnsPacket* pack)
{
    this->pack = pack;
    this->buf = nullptr;
    this->sock = nullptr;
}

request::request(const uv_buf_t* buffer, ssize_t size, const sockaddr* addr, uv_udp_t* u)
    : nsize(size)
{
    buf = global_server::get_server().new_uv_buf_t();
    buf->len = size;
    buf->base = buffer->base;
    sock = utils::make(addr);
    udp = u;
}

request::~request()
{
    if (likely(sock != nullptr)) {
        utils::free_buffer(buf->base);
        utils::destroy(sock);
    }
    global_server::get_server().delete_uv_buf_t(buf);
}

// forward response
forward_response::~forward_response()
{
    utils::free_buffer(response_buffer->base);
    global_server::get_server().delete_uv_buf_t(response_buffer);
}

// forward_item

forward_item::forward_item(DnsPacket* packet, const request_pointer& rp) : req(rp), pack(packet)
{
    response_send = false;
    if (unlikely(rp->buf != nullptr)) {
        origin_id = *reinterpret_cast<uint16_t*>(rp->buf->base);
    }
    pthread_spin_init(&_lock, PTHREAD_PROCESS_PRIVATE);
}

forward_item::~forward_item()
{
    pthread_spin_destroy(&_lock);
    delete pack;
}
