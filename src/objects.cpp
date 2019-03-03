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
#include "utils.h"

using namespace dns;
using namespace objects;

found_response::found_response(DnsPacket* pack, const request_pointer& rq)
    : response(rq), packet(pack)
{
    response_buffer = new uv_buf_t;
    response_buffer->base = reinterpret_cast<char*>(pack->get_data());
    response_buffer->len = pack->get_size();
}

found_response::~found_response()
{
    delete packet;
    delete response_buffer;
}

// response
response::response(const request_pointer& p) : req(p) {}

response::~response() {}

// request
request::request(const uv_buf_t* buffer, ssize_t size, const sockaddr* addr) : nsize(size)
{
    buf = utils::make(buffer);
    buf->len = size;
    sock = utils::make(addr);
}

request::~request()
{
    utils::free_buffer(buf->base);
    utils::destroy(buf);
    utils::destroy(sock);
}

// forward response
forward_response::~forward_response()
{
    utils::free_buffer(response_buffer->base);
    delete response_buffer;
}

// forward_item

forward_item::forward_item(DnsPacket* packet, const request_pointer& rp) : req(rp), pack(packet)
{
    response_send = false;
    origin_id = *reinterpret_cast<uint16_t*>(rp->buf->base);
    pthread_spin_init(&_lock, PTHREAD_PROCESS_PRIVATE);
}

forward_item::~forward_item()
{
    pthread_spin_destroy(&_lock);
    delete pack;
}
