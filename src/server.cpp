/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// server.cpp: global_server class implement

#include "server.h"
#include "athdns.h"
#include "dns.h"
#include "logging.h"

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cstring>
#include <functional>
#include <utility>

#ifdef HAVE_DOH_SUPPORT
#include "doh.h"
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#endif
#endif

using namespace hash;
using namespace dns;
using namespace objects;

using std::shared_ptr;
using std::unique_ptr;
using std::weak_ptr;

global_server* global_server::server_instance = nullptr;

//////////////////////////////////////////////////////////////////////
#ifdef HAVE_DOH_SUPPORT
ip_address* global_server::sync_internal_query_A(const char* domain)
{
    ip_address* ret = nullptr;
    pthread_mutex_lock(sync_query_mutex);
    auto node = table->get(domain);
    if (node != nullptr) {
        auto a = node->get_record_A();
        if (a != nullptr) {
            ret = new ip_address(*a);
            TRACE("internal DNS Query, cached response: {0} -> {1}", domain, *ret);
        }
    } else {
        dns_package_builder builder;
        dns_package_builder::basic_query_package(builder, domain);
        DnsPacket* pack = builder.build();
        pack->parse();
        request* req = new request(pack);
        uv_buf_t* buf = new_uv_buf_t();
        buf->base = reinterpret_cast<char*>(pack->get_data());
        buf->len = pack->get_size();
        req->buf = buf;
        forward_response* item = new forward_response(req);
        forward_item_submit(item);
        pthread_barrier_wait(internal_barrier);

        node = table->get(domain);
        if (node != nullptr) {
            ret = node->get_record_A();
            if (ret != nullptr) {
                TRACE("internal DNS Query, forward response: {0} -> {1}", domain, *ret);
            }
        }
    }
    pthread_mutex_unlock(sync_query_mutex);
    return ret;
}
#endif

void global_server::add_remote_address(uint32_t ip)
{
    remote::udp_nameserver* ns = new remote::udp_nameserver(ip);
    remote_address.emplace_back(ns);
}

void global_server::set_log_file(const CH* path)
{
    log_file = path;
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd == -1) {
        ERROR("Open log file {0} failed: {1}", path, strerror(errno));
        return;
    } else {
        //utils::lostream::set_dest(fd);
    }
}

void global_server::init_server_loop()
{
    uv_main_loop = uv_default_loop();

    auto status = uv_timer_init(uv_main_loop, &timer);
    utils::check_uv_return_status(status, "timer reporter init");

    if (listen_address.size() == 0) {
        listen_address.emplace_back(std::make_tuple(strdup("0.0.0.0"), 53, nullptr, nullptr));
    }

    for (auto& listen : listen_address) {
        sockaddr_in* addr = new sockaddr_in;
        uv_udp_t* udp = new uv_udp_t;

        status = uv_udp_init(uv_main_loop, udp);
        utils::check_uv_return_status(status, "uv init");

        const char* address = std::get<0>(listen);
        const uint16_t port = std::get<1>(listen);
        status = uv_ip4_addr(address, port, addr);
        utils::check_uv_return_status(status, "uv set ipv4 addr");

        sockaddr* sock = reinterpret_cast<sockaddr*>(addr);
        status = uv_udp_bind(udp, sock, UV_UDP_REUSEADDR);
        if (likely(status == 0)) {
            INFO("bind success on {0}:{1}", address, port);
        } else {
            FATAL("bind failed on {0}:{1}. {2}", address, port, uv_strerror(status));
        }

        auto p = std::make_tuple(address, port, sock, udp);
        listen.swap(p);
    }

    static const auto& async_work_stop_loop = [](uv_async_t* work) {
        auto server = reinterpret_cast<global_server*>(work->data);
        static const auto& stop_cb = [](uv_handle_t* t, void*) { uv_close(t, nullptr); };

        for (auto& listen : server->listen_address) {
            uv_udp_recv_stop(std::get<3>(listen));
        }

        uv_timer_stop(&server->timer);
        uv_stop(server->uv_main_loop);
        uv_walk(server->uv_main_loop, stop_cb, nullptr);

        for (auto& ns : server->remote_address) {
            ns->stop_remote();
        }
    };

    static const auto& async_work_sending_response_cb = [](uv_async_t*) {
        static auto& queue = global_server::get_server().response_sending_queue;
        static auto lock = global_server::get_server().response_sending_queue_lock;

        static const auto& send_complete_cb = [](uv_udp_send_t* send, int flag) {
            if (unlikely(flag != 0)) {
                WARN("sending failed: {0}", uv_strerror(flag));
            }
            global_server::get_server().delete_uv_udp_send_t(send);
        };

        pthread_mutex_lock(lock);
        while (queue.size() > 0) {
            auto item = queue.front();
            queue.pop();
            auto send = global_server::get_server().new_uv_udp_send_t();
            auto udp = item->get_request()->udp;
            auto buf = item->get_buffer();
            auto sock = item->get_sock();
            uv_udp_send(send, udp, buf, 1, sock, send_complete_cb);
        }
        pthread_mutex_unlock(lock);
    };

    status = uv_async_init(uv_main_loop, async_works, async_work_stop_loop);
    utils::check_uv_return_status(status, "init async stop");

    status = uv_async_init(uv_main_loop, sending_response_works, async_work_sending_response_cb);
    utils::check_uv_return_status(status, "init async send");
    uv_timer_init(uv_main_loop, &current_time_timer);
    utils::check_uv_return_status(status, "current_timer");
}

void global_server::set_static_ip(const string& domain, uint32_t ip)
{
    record_node_A* static_record = new record_node_A(domain.c_str(), ip);
    table->put(static_record);
}

void global_server::add_static_ip(const string& domain, uint32_t ip)
{
    if (static_address == nullptr) {
        static_address = new std::vector<static_address_type>;
    }
    static_address->emplace_back(std::make_tuple(domain, ip));
}

void global_server::init_server()
{
    if (table == nullptr) {
        table = new hash::hashtable(cache_count);
    }
    if (static_address != nullptr) {
        for (auto& sa : *static_address) {
            auto& domain = std::get<0>(sa);
            auto ip = std::get<1>(sa);
            set_static_ip(domain, ip);
        }
        delete static_address;
        static_address = nullptr;
    }
    init_server_loop();
    if (unlikely(remote_address.size() == 0)) {
        ERROR("empty remote nameserver, reject to startup. exiting...");
        exit(1);
    } else {
        for (size_t i = 0; i < remote_address.size(); i++) {
            remote_address[i]->set_index(i);
        }
    }
    current_time_timer.data = &current_time;
#ifdef HAVE_DOH_SUPPORT
    init_ssl_libraries();
#endif
}

void global_server::start_server()
{
    // here is sort of upstream servers.
    // simple stable insert-sort
    std::vector<remote::abstract_nameserver*> servers;
    std::for_each(remote_address.begin(), remote_address.end(), [&](auto& itor) {
        if (itor->get_nameserver_type() == remote::remote_nameserver_type::doh) {
            servers.emplace_back(itor);
            itor = nullptr;
        }
    });
    std::for_each(remote_address.begin(), remote_address.end(), [&](auto itor) {
        if (itor != nullptr) {
            servers.emplace_back(itor);
        }
    });
    std::swap(servers, remote_address);

    for (auto& ns : remote_address) {
        ns->start_remote();
    }

    static const auto& current_time_timer_func = [](uv_timer_t* p) {
        static auto ct = reinterpret_cast<utils::atomic_number<time_t>*>(p->data);
        static utils::atomic_int count(0);
        if (unlikely(count++ % 600 == 0)) {
            ct->reset(time(nullptr));
        } else {
            ct->operator++();
        }
    };
    static const auto& report_func = [](uv_timer_t*) {
        static auto& server = global_server::get_server();
        int forward = server.get_total_forward_cound();
        int total = server.get_total_request();
        auto hit = total - forward;
        double percent = 0;
        if (likely(total != 0)) {
            percent = (hit * 1.0) / total * 100;
        }
        INFO(
            "report: requests {0}, hit {1}, rate {2:.2f}% "
            "forward {3}, saved {4}, memory {5} KB ",
            total,
            total - forward,
            percent,
            forward,
            server.get_hashtable_size(),
            utils::read_rss());
    };
    int reportt = timer_timeout * 1000;

    uv_timer_start(&timer, report_func, reportt, reportt);
    uv_timer_start(&current_time_timer, current_time_timer_func, 1000, 1000);
    for (auto& listen : listen_address) {
        uv_udp_recv_start(
            std::get<3>(listen), uvcb_server_incoming_alloc, uvcb_server_incoming_recv);
    }

    uv_run(uv_main_loop, UV_RUN_DEFAULT);
}

global_server::~global_server()
{
    if (uv_main_loop != nullptr) {
        uv_loop_close(uv_main_loop);
    }
    if (table != nullptr) {
        delete table;
    }
    for (auto& ns : remote_address) {
        delete ns;
    }
    for (auto& listen : listen_address) {
        delete[] std::get<0>(listen);
        delete std::get<2>(listen);
        delete std::get<3>(listen);
    }

    pthread_spin_lock(&forward_table_lock);
    forward_table.clear();
    pthread_spin_unlock(&forward_table_lock);
    pthread_spin_destroy(&forward_table_lock);
    pthread_mutex_destroy(response_sending_queue_lock);

#ifdef HAVE_DOH_SUPPORT
    pthread_mutex_destroy(sync_query_mutex);
    pthread_barrier_destroy(internal_barrier);

    delete internal_barrier;
    delete sync_query_mutex;
#endif

    delete response_sending_queue_lock;
    delete async_works;
    delete sending_response_works;
}

global_server::global_server()
    : forward_id(utils::rand_value() & 0xffff),
      queue_lock(),
      queue_sem(),
      sending_lock(PTHREAD_MUTEX_INITIALIZER),
      uv_buf_t_pool(256),
      uv_udp_send_t_pool(100)
{
    response_sending_queue_lock = new pthread_mutex_t;
#ifdef HAVE_DOH_SUPPORT
    sync_query_mutex = new pthread_mutex_t;
    pthread_mutex_init(sync_query_mutex, nullptr);
    internal_barrier = new pthread_barrier_t;
    pthread_barrier_init(internal_barrier, nullptr, 2);
#endif
    total_request_count = 0;
    total_request_forward_count = 0;
    timeout_requery = false;
    parallel_query = false;
    default_ttl = 256;
    cache_count = 3000;
    log_file = "";
    uv_main_loop = nullptr;
    static_address = nullptr;
    timer_timeout = 5;
    forward_type = FT_ALL;
    pthread_spin_init(&queue_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&forward_table_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_mutex_init(response_sending_queue_lock, nullptr);
    sem_init(&queue_sem, 0, 0);
    table = nullptr;
    async_works = new uv_async_t;
    async_works->data = this;
    sending_response_works = new uv_async_t;
}

void global_server::do_stop()
{
    INFO("stopping server.");
#ifndef ATHDNS_MEM_DEBUG
    DTRACE(
        "uv_buf_t allocator max allocated {0},  uv_udp_send_t allocator max allocated {1}, "
        "char* buffer max allocated {2}",
        uv_buf_t_pool.get_max_allocated(),
        uv_udp_send_t_pool.get_max_allocated(),
        utils::get_max_buffer_allocate());
    DTRACE(
        "uv_buf_t now allocated {0}, uv_udp_send_t now allocated {1},"
        " char buffer now allocated {2}",
        uv_buf_t_pool.get_current_allocated(),
        uv_udp_send_t_pool.get_current_allocated(),
        utils::get_current_buffer_allocate());
#endif
    uv_async_send(async_works);
}

void global_server::set_server_log_level(utils::log_level ll)
{
    logging::set_default_level(ll);
}

void global_server::forward_item_all(weak_ptr<forward_response> forward)
{
    for (auto& ns : remote_address) {
        send_object* obj = new send_object;
        if (!forward.expired()) {
            auto item = forward.lock().get();
            obj->bufs = item->get_request()->buf;
            obj->bufs_count = 1;
            obj->sock = ns->get_sock();
            ns->send(obj);
            ns->increase_forward();
            DTRACE("OUT request {0} -> {1}", item->get_request()->pack->getQuery().getName(), *ns);
        } else {
            delete obj;
        }
    }
}

void global_server::forward_item_submit(forward_response* forward)
{
    increase_forward();
    unique_ptr<forward_response> resp(forward);
    auto fid = forward_id++;
    forward->set_forward_id(fid);
    pthread_spin_lock(&forward_table_lock);
    const auto ins = forward_table.insert({fid, std::move(resp)});
    pthread_spin_unlock(&forward_table_lock);
    weak_ptr<forward_response> send_resp(ins.first->second);

    switch (forward_type) {
        case FT_ALL:
            return forward_item_all(send_resp);
        default:
            assert(false);
    }
}

void global_server::send_response(std::shared_ptr<response> resp)
{
    pthread_mutex_lock(response_sending_queue_lock);
    response_sending_queue.emplace(resp);
    pthread_mutex_unlock(response_sending_queue_lock);
    uv_async_send(sending_response_works);
}

void global_server::response_from_remote(uv_buf_t* buf, remote::abstract_nameserver* ns)
{
    uint16_t* p = reinterpret_cast<uint16_t*>(buf->base);
    uint16_t forward_id = ntohs(*p);

#ifdef DTRACE_OUTPUT
    DnsPacket* dpack = DnsPacket::fromDataBuffer(buf);
    dpack->parse();
    string node_string;
    record_node* node = dpack->generate_record_node();
    if (node != nullptr) {
        node->to_string(node_string);
        DTRACE("IN response from {0}: {1}->{2}", *ns, dpack->getQuery().getName(), node_string);
        delete node;
    }
    delete dpack;
#endif

    pthread_spin_lock(&forward_table_lock);
    auto req = forward_table.find(forward_id);
    if (req == forward_table.end()) {
        pthread_spin_unlock(&forward_table_lock);
        utils::free_buffer(buf->base);
        delete_uv_buf_t(buf);
    } else {
        const static shared_ptr<forward_response> empty(nullptr);
        shared_ptr<forward_response> pointer = req->second;
        forward_table.erase(req);
        pthread_spin_unlock(&forward_table_lock);
        DnsPacket* pack = DnsPacket::fromDataBuffer(buf);
        pack->parse();
        record_node* node = pack->generate_record_node();
        cache_add_node(node);
        delete pack;
        pointer->set_response(buf->base, buf->len);
#ifdef HAVE_DOH_SUPPORT
        if (likely(pointer->get_sock() != nullptr)) {
#endif
            send_response(std::move(pointer));
#ifdef HAVE_DOH_SUPPORT
        } else {
            utils::free_buffer(buf->base);
            delete_uv_buf_t(buf);
            pthread_barrier_wait(internal_barrier);
        }
#endif
    }
}

void global_server::cache_add_node(record_node* node)
{
    if (table != nullptr) {
        table->put(node);
    }
}

void global_server::config_listen_at(const char* ip, uint16_t port)
{
    listen_address.emplace_back(std::make_tuple(ip, port, nullptr, nullptr));
}

#ifdef HAVE_DOH_SUPPORT
void global_server::add_doh_nameserver(const char* url)
{
    remote::doh_nameserver* ns = new remote::doh_nameserver(url);
    remote_address.emplace_back(ns);
}
#endif

void global_server::init_ssl_libraries()
{
#ifdef HAVE_DOH_SUPPORT
#ifdef HAVE_OPENSSL
    SSL_library_init();
    SSL_load_error_strings();
#else
#endif
#endif
}

void global_server::destroy_ssl_libraries()
{
#ifdef HAVE_DOH_SUPPORT
#ifdef HAVE_OPENSSL
#endif
#endif
}
