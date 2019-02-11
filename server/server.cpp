
#include "server.h"
#include "dns.h"
#include "dnsserver.h"

#include "glog/logging.h"
using namespace google;

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>
#include <iostream>


global_server* global_server::server_instance = nullptr;

using namespace dns;

void global_server::add_remote_address(uint32_t ip)
{
    for (auto& ns : remote_address) {
        if (ns == ip) {
            //TODO nameserver exists. Here should have a warning
            DLOG(INFO) << "exists.";
            return;
        }
    }

    remote_address.emplace_back(ip);
    string str;
    DLOG(INFO) << "add remote nameserver ";
}

void global_server::set_log_file(const CH* path)
{
    log_file = path;
    int fd   = open(path, O_WRONLY | O_APPEND | O_CREAT);
    if (fd == -1) {
        DLOG(ERROR) << "Open log file " << path << " failed: " << strerror(errno);
        return;
    } else {
        //utils::lostream::set_dest(fd);
    }
}

void global_server::init_server_loop()
{
    const static auto check = [=](int st, const char* when) {
        if (st < 0) {
            DLOG(ERROR) << when << " error: " << uv_strerror(st);
            exit(0);
        }
    };

    struct sockaddr_in addr;
    uv_main_loop = uv_default_loop();
    auto status  = uv_udp_init(uv_main_loop, &server_socket);

    check(status, "uv init");

    status = uv_ip4_addr("0.0.0.0", 53535, &addr);
    check(status, "uv set ipv4 addr");
    status =
        uv_udp_bind(&server_socket, reinterpret_cast<struct sockaddr*>(&addr), UV_UDP_REUSEADDR);
    check(status, "bind");
    status = uv_udp_recv_start(&server_socket, uv_handler_on_alloc, uv_handler_on_recv);
    check(status, "recv start");
}

void global_server::set_static_ip(const string& domain, uint32_t ip)
{
    using hash::hash_entry_A;
    hash_entry_A new_entry_A(domain.c_str(), ip_address(ip));
    hash->put(domain.c_str(), new_entry_A);
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
    if (hash != nullptr) {
        delete hash;
    } else {
        hash = new hash_table_type(cache_count);
    }

    if (static_address != nullptr) {
        for (auto& sa : *static_address) {
            auto& domain = std::get<0>(sa);
            auto ip      = std::get<1>(sa);
            set_static_ip(domain, ip);
        }
        delete static_address;
        static_address = nullptr;
    }
    pthread_create(&this->working_thread, nullptr, ::work_thread_fn, nullptr);
    init_server_loop();
}

global_server::~global_server()
{
    if (hash != nullptr) {
        delete hash;
    }
    if (uv_main_loop != nullptr) {
        uv_loop_close(uv_main_loop);
        free(uv_main_loop);
    }
}

void* work_thread_fn(void*)
{
    static auto& server     = global_server::get_server();
    static auto& rqueue     = server.get_queue();
    static auto* queue_lock = server.get_spinlock();
    static auto* queue_sem  = server.get_semaphore();
    static auto& htable     = server.get_hashtable();

    while (true) {
        sem_wait(queue_sem);
        pthread_spin_lock(queue_lock);
        auto item = rqueue.front();
        rqueue.pop();
        pthread_spin_unlock(queue_lock);
        auto name = item->getQuery().getName();
        auto id   = item->getQueryID();
        VLOG(INFO) << name << " " << id;
        // hash::hash_entry<const char*>* entry;
        // bool found = htable.get(name, *entry);
        // if (found) {
        //     VLOG(INFO) << name << " found in hashtable " << entry->to_string();
        // }
    }
}
