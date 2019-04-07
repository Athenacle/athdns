/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// remote.cpp: remote server implements

#include "remote.h"
#include "logging.h"
#include "server.h"

#ifdef HAVE_MBEDTLS
#include <mbedtls/error.h>
#include <mbedtls/sha1.h>
#endif

using namespace remote;

abstract_nameserver::~abstract_nameserver()
{
    delete upstream_socket;
    delete loop;
    delete stop_async;
    delete work_thread;
}

abstract_nameserver::abstract_nameserver(uint32_t __remote_ip, int __remote_port)
    : abstract_nameserver()
{
    remote_address.reset(__remote_ip);
    remote_port = __remote_port;
    init_socket();
}

abstract_nameserver::abstract_nameserver()
{
    remote_address.reset(0);
    remote_port = 0;
    index = 0;
    upstream_socket = nullptr;
    loop = new uv_loop_t;
    loop->data = this;
    stop_async = new uv_async_t;
    stop_async->data = this;
    work_thread = new pthread_t;
}

void abstract_nameserver::swap(abstract_nameserver& an)
{
    std::swap(remote_port, an.remote_port);
    std::swap(remote_address, an.remote_address);
    std::swap(request_forward_count, an.request_forward_count);
    std::swap(response_count, an.response_count);
    upstream_socket = an.upstream_socket;
    an.upstream_socket = nullptr;
    index = an.index;
}

bool abstract_nameserver::init_socket()
{
    if (upstream_socket != nullptr) {
        return true;
    }
    upstream_socket = new sockaddr_in;
    string ip_string;
    remote_address.to_string(ip_string);
    auto ret = uv_ip4_addr(ip_string.c_str(), remote_port, upstream_socket);
    if (ret < 0) {
        ERROR("init_socket failed");
    }
    return ret == 0;
}

void abstract_nameserver::destroy_nameserver()
{
    uv_loop_close(loop);
}

void abstract_nameserver::set_socket(const ip_address& ip, uint16_t port)
{
    remote_address = ip;
    remote_port = port;
    init_socket();
}

void abstract_nameserver::start_upstream()
{
    const auto async_cb = [](uv_async_t* async) {
        abstract_nameserver* an = reinterpret_cast<abstract_nameserver*>(async->data);
        static const auto& walk = [](uv_handle_t* t, void*) {
            if (t != nullptr)
                uv_close(t, nullptr);
        };
        an->implement_stop_cb();
        uv_walk(an->get_loop(), walk, nullptr);
        uv_stop(an->get_loop());
        uv_loop_close(an->get_loop());
    };
    uv_loop_init(loop);
    uv_async_init(loop, stop_async, async_cb);
    stop_async->data = this;
    implement_do_startup();
}

void abstract_nameserver::stop_upstream()
{
    uv_async_send(stop_async);
    pthread_join(*work_thread, nullptr);
}

// remote_nameserver

udp_nameserver::~udp_nameserver()
{
    delete udp_handler;
    delete async_send;
    delete sending_queue_mutex;
}

udp_nameserver::udp_nameserver(const ip_address&& addr, int port)
    : udp_nameserver(addr.get_address(), port)
{
}

udp_nameserver::udp_nameserver(uint32_t addr, int p) : remote::abstract_nameserver(addr, p)
{
    async_send = new uv_async_t;
    udp_handler = new uv_udp_t;
    sending_queue_mutex = new pthread_mutex_t;

    async_send->data = udp_handler->data = this;
    pthread_mutex_init(sending_queue_mutex, nullptr);
}

void udp_nameserver::init_upstream()
{
    static const auto& complete = [](uv_udp_send_t* send, int flag) {
        if (unlikely(flag < 0)) {
            WARN("send error {0}", uv_err_name(flag));
        }

        auto sending = reinterpret_cast<uv_udp_sending*>(send->data);
        delete sending->obj;
        delete sending;
        global_server::get_server().delete_uv_udp_send_t(send);
    };

    const auto& send_cb = [](uv_async_t* send) {
        auto sending_obj = reinterpret_cast<udp_nameserver*>(send->data);

        pthread_mutex_lock(sending_obj->sending_queue_mutex);
        while (sending_obj->sending_queue.size() > 0) {
            auto i = sending_obj->sending_queue.front();
            sending_obj->sending_queue.pop();
            uv_udp_send_t* sending = global_server::get_server().new_uv_udp_send_t();
            sending->data = i;
            auto flag = uv_udp_send(
                sending, i->handle, i->obj->bufs, i->obj->bufs_count, i->obj->sock, complete);
            if (unlikely(flag < 0)) {
                ERROR("send failed: {0}", uv_err_name(flag));
            }
        }
        pthread_mutex_unlock(sending_obj->sending_queue_mutex);
    };

    auto l = get_loop();
    uv_async_init(l, async_send, send_cb);
    uv_udp_init(l, udp_handler);
}


void udp_nameserver::send(objects::send_object* obj)
{
    uv_udp_sending* sending = new uv_udp_sending;
    sending->lock = sending_queue_mutex;
    sending->handle = udp_handler;
    sending->obj = obj;

    pthread_mutex_lock(sending_queue_mutex);
    sending_queue.emplace(sending);
    pthread_mutex_unlock(sending_queue_mutex);
    uv_async_send(async_send);
}

void udp_nameserver::destroy_remote()
{
    pthread_mutex_destroy(sending_queue_mutex);
    destroy_nameserver();
}

void udp_nameserver::implement_do_startup()
{
    static const auto& thread_func = [](void* param) -> void* {
        auto pointer = reinterpret_cast<udp_nameserver*>(param);
        auto loop = pointer->get_loop();
        auto udp = pointer->get_udp_handler();
        uv_udp_recv_start(udp, uvcb_server_incoming_alloc, uvcb_remote_udp_recv);
        uv_run(loop, UV_RUN_DEFAULT);
        return nullptr;
    };

    init_upstream();
    pthread_create(get_thread(), nullptr, thread_func, this);
}


using namespace dns;
using namespace objects;

response::response(request* p) : req(p)
{
    response_buffer = nullptr;
}

response::~response()
{
    if (response_buffer != nullptr) {
        global_server::get_server().delete_uv_buf_t(response_buffer);
    }
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
    const uv_buf_t* buffer, ssize_t size, const sockaddr* addr, uv_udp_t* u, dns::dns_packet* p)
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
        delete sock;
        global_server::get_server().delete_uv_buf_t(buf);
    }
    delete pack;
}


void forward_response::set_response(char* base, uint32_t size)
{
    response::set_response(base, size);
    *reinterpret_cast<uint16_t*>(response_buffer->base) = utils::htons(origin_id);
}

// forward response
forward_response::~forward_response() {}
