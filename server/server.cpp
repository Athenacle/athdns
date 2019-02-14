#include "server.h"
#include "dns.h"
#include "dnsserver.h"
#include "logging.h"

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>
#include <ctime>

using namespace hash;

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
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT);
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

    int reportt = timer_timeout * 1000;

    struct sockaddr_in addr;
    uv_main_loop = uv_default_loop();

    auto status = uv_timer_init(uv_main_loop, &timer);
    check(status, "timer report init");

    status = uv_timer_start(&timer, uvcb_timer_reporter, reportt, reportt);

    check(status, "report timer start");

    status = uv_udp_init(uv_main_loop, &server_socket);

    check(status, "uv init");

    const int default_port = 53535;
    const auto default_address = "0.0.0.0";

    status = uv_ip4_addr(default_address, default_port, &addr);
    check(status, "uv set ipv4 addr");
    status =
        uv_udp_bind(&server_socket, reinterpret_cast<struct sockaddr*>(&addr), UV_UDP_REUSEADDR);
    check(status, "bind");

    if (status == 0) {
        INFO("bind success on {0}:{1}", default_address, default_port);
    }
    status =
        uv_udp_recv_start(&server_socket, uvcb_server_incoming_alloc, uvcb_server_incoming_recv);

    check(status, "recv start");

    pthread_create(&this->working_thread, nullptr, ::work_thread_fn, nullptr);
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
}

global_server::~global_server()
{
    if (uv_main_loop != nullptr) {
        uv_loop_close(uv_main_loop);
    }
    if (table != nullptr) {
        delete table;
    }
}

void global_server::do_stop()
{
    INFO("Stopping server.");
    uv_timer_stop(&timer);
    uv_stop(uv_main_loop);
}

void global_server::set_server_log_level(utils::log_level ll)
{
    logging::set_default_level(ll);
}

void uv_udp_send_handler(uv_udp_send_t* req, int status)
{
    delete_item* item = reinterpret_cast<delete_item*>(req->data);
    DEBUG("deleteing send status {0}", status);
    if (unlikely(status < 0)) {
        ERROR("DNS reply send  failed: {0}", uv_strerror(status));
    }
    item->do_delete();
    delete item;
    ::free(req);
}


void* work_thread_fn(void*)
{
    static auto& server = global_server::get_server();
    static auto& rqueue = server.get_queue();
    static auto queue_lock = server.get_spinlock();
    static auto queue_sem = server.get_semaphore();
    static auto& table = server.get_hashtable();
    static auto handle = server.get_server_socket();

    prctl(PR_SET_NAME, "working");

    while (true) {
        sem_wait(queue_sem);
        pthread_spin_lock(queue_lock);
        auto item = rqueue.front();
        rqueue.pop();
        pthread_spin_unlock(queue_lock);
        uv_buf_t* incoming_buf = std::get<0>(item);
        DnsPacket* pack = DnsPacket::fromDataBuffer(reinterpret_cast<uint8_t*>(incoming_buf->base),
                                                    incoming_buf->len);
        const sockaddr* incoming_sock = std::get<1>(item);
        pack->parse();
        auto name = pack->getQuery().getName();
        if (unlikely(strcmp(name, "stop.dnsserver.ok") == 0)) {
            // stop server
            utils::destroy(incoming_buf->base);
            utils::destroy(incoming_buf);
            utils::destroy(incoming_sock);
            delete pack;
            break;
        }
        auto id = pack->getQueryID();
        record_node* found = table.get(name);
        if (found == nullptr) {
            DDEBUG("Input DNS Request:  ID #{0:x} -> {1}. NOT Found", id, name);
            utils::destroy(incoming_buf->base);
            utils::destroy(incoming_buf);
            utils::destroy(incoming_sock);
            delete pack;
            //TODO implements this.
        } else {
            string text;
            found->to_string(text);
            DEBUG("Input DNS Request:  ID #{0:x} -> {1} : {2}", id, name, text);
            DnsPacket* ret = DnsPacket::build_response_with_records(pack, found);
            uv_udp_send_t* send = reinterpret_cast<uv_udp_send_t*>(malloc(sizeof(uv_udp_send_t)));

            uv_buf_t* buf = reinterpret_cast<uv_buf_t*>(malloc(sizeof(uv_buf_t)));

            buf->base = reinterpret_cast<char*>(ret->get_data());
            buf->len = ret->get_size();
            utils::destroy(incoming_buf->base);
            utils::destroy(incoming_buf);

            delete_item* ditem = new delete_item(std::time(nullptr), ret, buf, incoming_sock);
            send->data = ditem;
            auto send_status =
                uv_udp_send(send, handle, buf, 1, incoming_sock, uv_udp_send_handler);

            if (send_status < 0)
                DEBUG("send error: {0}", uv_strerror(send_status));
            delete pack;
        }
    }
    server.do_stop();

    return nullptr;
}
