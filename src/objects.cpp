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

void time_object::operator()()
{
    clock_gettime(ATHDNS_CLOCK_GETTIME_FLAG, &t);
}

time_object::time_object()
{
    this->operator()();
}

uint64_t time_object::diff_to_ns(const time_object& begin, const time_object& end)
{
    auto s = end.t.tv_sec - begin.t.tv_sec;
    uint64_t ret = s * 1000000000 + end.t.tv_nsec - begin.t.tv_nsec;
    return ret;
}

double time_object::diff_to_ms(const time_object& begin, const time_object& end)
{
    return diff_to_ns(begin, end) / 1000000.0;
}

double time_object::diff_to_us(const time_object& begin, const time_object& end)
{
    return diff_to_ns(begin, end) / 1000.0;
}

time_object::time_object(const time_object& __t)
{
    this->t.tv_nsec = __t.t.tv_nsec;
    this->t.tv_sec = __t.t.tv_sec;
}

bool time_object::operator==(const time_object& __t) const
{
    return t.tv_sec == __t.t.tv_sec;
}

time_object& time_object::operator=(time_object&& __t)
{
    std::swap(t, __t.t);
    return *this;
}
