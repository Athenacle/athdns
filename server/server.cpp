
#include "server.h"
#include "dns.h"
#include "dnsserver.h"
#include "logging.h"

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
            INFO("exists.");
            return;
        }
    }

    remote_address.emplace_back(ip);
}

void global_server::set_log_file(const CH* path)
{
    log_file = path;
    int fd   = open(path, O_WRONLY | O_APPEND | O_CREAT);
    if (fd == -1) {
        ERROR("Open log file {0} failed: {1}", path, strerror(errno));
        return;
    } else {
        //utils::lostream::set_dest(fd);
    }
}

void global_server::init_server_loop()
{
    const static auto check = [=](int st, const char* when) {
        if (st < 0) {
            ERROR("error in libuv when {0}: {1}", when, uv_strerror(st));
            exit(0);
        }
    };

    struct sockaddr_in addr;
    uv_main_loop = uv_default_loop();
    auto status  = uv_udp_init(uv_main_loop, &server_socket);

    check(status, "uv init");

    const int default_port     = 53535;
    const auto default_address = "0.0.0.0";

    status = uv_ip4_addr(default_address, default_port, &addr);
    check(status, "uv set ipv4 addr");
    status =
        uv_udp_bind(&server_socket, reinterpret_cast<struct sockaddr*>(&addr), UV_UDP_REUSEADDR);
    check(status, "bind");
    if (status == 0) {
        INFO("bind success on {0}:{1}", default_address, default_port);
    }
    status = uv_udp_recv_start(&server_socket, uv_handler_on_alloc, uv_handler_on_recv);
    check(status, "recv start");
}

void global_server::set_static_ip(const string& domain, uint32_t ip) {}

void global_server::add_static_ip(const string& domain, uint32_t ip)
{
    if (static_address == nullptr) {
        static_address = new std::vector<static_address_type>;
    }
    static_address->emplace_back(std::make_tuple(domain, ip));
}

void global_server::init_server()
{
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
    if (uv_main_loop != nullptr) {
        uv_loop_close(uv_main_loop);
        free(uv_main_loop);
    }
}

void global_server::set_server_log_level(utils::log_level ll)
{
    logging::set_default_level(ll);
}

void* work_thread_fn(void*)
{
    static auto& server     = global_server::get_server();
    static auto& rqueue     = server.get_queue();
    static auto* queue_lock = server.get_spinlock();
    static auto* queue_sem  = server.get_semaphore();

    while (true) {
        sem_wait(queue_sem);
        pthread_spin_lock(queue_lock);
        auto item = rqueue.front();
        rqueue.pop();
        pthread_spin_unlock(queue_lock);
        auto name = item->getQuery().getName();
        auto id   = item->getQueryID();
        DEBUG("Input DNS Request:  ID #{0:x} -> {1}", id, name);
    }
}
