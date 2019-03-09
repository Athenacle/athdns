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

using namespace remote;

abstract_nameserver::~abstract_nameserver()
{
    pthread_mutex_destroy(sending_lock);
    delete sending_lock;
    delete sock;
    delete loop;
    delete stop_async;
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
    sending_lock = new pthread_mutex_t;
    pthread_mutex_init(sending_lock, nullptr);
    index = 0;
    sock = nullptr;
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
    std::swap(sending, an.sending);
    std::swap(request_forward_count, an.request_forward_count);
    std::swap(response_count, an.response_count);
    sock = an.sock;
    an.sock = nullptr;
    index = an.index;
}

bool abstract_nameserver::init_socket()
{
    sock = new sockaddr_in;
    string ip_string;
    remote_address.to_string(ip_string);
    auto ret = uv_ip4_addr(ip_string.c_str(), remote_port, sock);
    return ret == 0;
}

int abstract_nameserver::clean_sent()
{
    int count = 0;
    pthread_mutex_lock(sending_lock);
    const auto& end = sending.end();
    for (auto itor = sending.begin(); itor != end;) {
        if (itor->second->get_response_send()) {
            itor = sending.erase(itor);
            count++;
        } else {
            ++itor;
        }
    }
    pthread_mutex_unlock(sending_lock);
    return count;
}

void abstract_nameserver::insert_sending(const sending_item_type& pair)
{
    pthread_mutex_lock(sending_lock);
    sending.insert(pair);
    pthread_mutex_unlock(sending_lock);
}

bool abstract_nameserver::find_erase(uint16_t id)
{
    pthread_mutex_lock(sending_lock);
    auto itor = sending.find(id);
    auto found = itor != sending.end();
    if (found) {
        sending.erase(itor);
    }
    pthread_mutex_unlock(sending_lock);
    return found;
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

void abstract_nameserver::start_remote()
{
    const auto async_cb = [](uv_async_t* async) {
        abstract_nameserver* an = reinterpret_cast<abstract_nameserver*>(async->data);

        static const auto& walk = [](uv_handle_t* t, void*) { uv_close(t, nullptr); };
        an->implement_stop_cb();
        uv_walk(an->get_loop(), walk, nullptr);
        uv_stop(an->get_loop());
    };

    uv_loop_init(loop);
    uv_async_init(loop, stop_async, async_cb);
    implement_do_startup();
}

void abstract_nameserver::stop_remote()
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

void udp_nameserver::init_remote()
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
        auto udp = pointer->get_udp_hander();
        uv_udp_recv_start(udp, uvcb_server_incoming_alloc, uvcb_remote_udp_recv);
        uv_run(loop, UV_RUN_DEFAULT);
        return nullptr;
    };

    init_remote();
    pthread_create(get_thread(), nullptr, thread_func, this);
}

#ifdef HAVE_DOH_SUPPORT

doh_nameserver::doh_nameserver(const char* u)
{
    url = utils::strdup(u);
}

doh_nameserver::~doh_nameserver()
{
    utils::strfree(url);
}

void doh_nameserver::implement_do_startup()
{
    //TODO: implement this
}

void doh_nameserver::implement_stop_cb()
{
    //TODO: implement this
}

void doh_nameserver::send(objects::send_object*)
{
    //TODO: implement this
}

void doh_nameserver::init_remote()
{
    //TODO: implement this
}

void doh_nameserver::destroy_remote()
{
    //TODO: implement this
}

#endif
