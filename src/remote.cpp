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
}

abstract_nameserver::abstract_nameserver(uint32_t __remote_ip, int __remote_port)
    : abstract_nameserver()
{
    remote_address.reset(__remote_ip);
    remote_port = __remote_port;
}

abstract_nameserver::abstract_nameserver()
{
    sending_lock = new pthread_mutex_t;
    pthread_mutex_init(sending_lock, nullptr);
    index = 0;
    sock = nullptr;
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

// remote_nameserver

remote_nameserver::~remote_nameserver()
{
    delete loop;
    delete udp_handler;
    delete async_send;
    delete async_stop;
    delete lock;
}

remote_nameserver::remote_nameserver(const ip_address&& addr, int port)
    : remote_nameserver(addr.get_address(), port)
{
}

remote_nameserver::remote_nameserver(uint32_t addr, int p) : remote::abstract_nameserver(addr, p)
{
    loop = new uv_loop_t;
    async_send = new uv_async_t;
    async_stop = new uv_async_t;
    udp_handler = new uv_udp_t;
    lock = new pthread_mutex_t;

    async_send->data = async_stop->data = loop->data = udp_handler->data = this;
    pthread_mutex_init(lock, nullptr);
}

void remote_nameserver::init_remote()
{
    const auto& stop_cb = [](uv_async_t* work) {
        auto pointer = reinterpret_cast<remote_nameserver*>(work->data);
        uv_udp_recv_stop(pointer->udp_handler);
        uv_walk(pointer->loop, [](uv_handle_t* t, void*) { uv_close(t, nullptr); }, nullptr);
        uv_stop(pointer->loop);
    };

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
        auto sending_obj = reinterpret_cast<remote_nameserver*>(send->data);

        pthread_mutex_lock(sending_obj->lock);
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
        pthread_mutex_unlock(sending_obj->lock);
    };

    init_socket();
    uv_loop_init(loop);
    uv_async_init(loop, async_stop, stop_cb);
    uv_async_init(loop, async_send, send_cb);
    uv_udp_init(loop, udp_handler);
}

void remote_nameserver::to_string(string& str) const
{
    get_ip_address().to_string(str);
    str.append(":").append(std::to_string(get_port()));
}

void remote_nameserver::send(objects::send_object* obj)
{
    uv_udp_sending* sending = new uv_udp_sending;
    sending->lock = lock;
    sending->handle = udp_handler;
    sending->obj = obj;

    pthread_mutex_lock(lock);
    sending_queue.emplace(sending);
    pthread_mutex_unlock(lock);
    uv_async_send(async_send);
}

void remote_nameserver::destroy_remote()
{
    pthread_mutex_destroy(lock);
    uv_loop_close(loop);
}

void remote_nameserver::start_remote()
{
    static const auto& thread_func = [](void* param) -> void* {
        auto pointer = reinterpret_cast<remote_nameserver*>(param);
        auto loop = pointer->get_loop();
        auto udp = pointer->get_udp_hander();
        uv_udp_recv_start(udp, uvcb_server_incoming_alloc, uvcb_remote_udp_recv);
        uv_run(loop, UV_RUN_DEFAULT);
        return nullptr;
    };

    init_remote();
    pthread_create(&thread, nullptr, thread_func, this);
}

void remote_nameserver::stop_remote()
{
    uv_async_send(async_stop);
    pthread_join(thread, nullptr);
}
