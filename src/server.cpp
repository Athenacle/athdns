#include "server.h"
#include "athdns.h"
#include "dns.h"
#include "logging.h"

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>
#include <ctime>

using namespace hash;
using namespace dns;
using namespace objects;

global_server* global_server::server_instance = nullptr;

void uv_udp_nameserver_runnable::swap(uv_udp_nameserver_runnable& ns)
{
    std::swap(loop, ns.loop);
    std::swap(udp, ns.udp);
    std::swap(async, ns.async);
}

void uv_udp_nameserver_runnable::start(uv_run_mode mode)
{
    uv_udp_recv_start(udp, uvcb_server_incoming_alloc, uvcb_remote_recv);
    uv_run(loop, mode);
}

void uv_udp_nameserver_runnable::stop()
{
    uv_async_send(async);
    pthread_join(thread, nullptr);
}

void uv_udp_nameserver_runnable::send(send_object* obj)
{
    count++;
    uv_udp_sending* sending = new uv_udp_sending;
    sending->lock = lock;
    sending->handle = udp;
    sending->obj = obj;

    pthread_mutex_lock(lock);
    sending_queue.emplace(sending);
    pthread_mutex_unlock(lock);

    uv_async_send(async_send);
}

void uv_udp_nameserver_runnable::destroy()
{
    pthread_mutex_destroy(lock);
    uv_loop_close(loop);
    delete loop;
    delete async_send;
    delete lock;
    delete udp;
    delete async;
}

void uv_udp_nameserver_runnable::init()
{
    lock = new pthread_mutex_t;
    async = new uv_async_t;
    udp = new uv_udp_t;
    loop = new uv_loop_t;

    pthread_mutex_init(lock, nullptr);
    uv_loop_init(loop);

    pthread_mutex_lock(lock);
    async_send = new uv_async_t;
    uv_async_init(loop, async, [](uv_async_t* work) {
        auto pointer = reinterpret_cast<uv_udp_nameserver_runnable*>(work->data);
        uv_udp_recv_stop(pointer->udp);
        uv_walk(pointer->loop, [](uv_handle_t* t, void*) { uv_close(t, nullptr); }, nullptr);
        uv_stop(pointer->loop);
    });
    uv_async_init(loop, async_send, uvcb_async_remote_send);
    async_send->data = this;
    async->data = this;

    pthread_mutex_unlock(lock);

    uv_udp_init(loop, udp);

    udp->data = this;
}

// remote nameserver
void remote_nameserver::send(send_object* obj)
{
    run.send(obj);
}
void remote_nameserver::to_string(string& str) const
{
    ip.to_string(str);
    str.append(":").append(std::to_string(port));
}

remote_nameserver::~remote_nameserver()
{
    delete sending_lock;
    if (sock != nullptr) {
        delete sock;
    }
}

remote_nameserver::remote_nameserver(remote_nameserver&& ns)
{
    index = ns.index;
    port = ns.port;
    sock = ns.sock;
    ip = ns.ip;

    sending_lock = ns.sending_lock;

    std::swap(run, ns.run);
    std::swap(request_forward_count, ns.request_forward_count);
    std::swap(response_count, ns.response_count);
    ns.sending_lock = nullptr;
    ns.sock = nullptr;
}

remote_nameserver::remote_nameserver(const ip_address&& addr, int port)
    : remote_nameserver(addr.get_address(), port)
{
}

remote_nameserver::remote_nameserver(uint32_t addr, int p) : ip(addr)
{
    index = 0;
    port = p;
    string ip_string;
    sock = new sockaddr_in;
    ip.to_string(ip_string);
    auto ret = uv_ip4_addr(ip_string.c_str(), port, sock);
    assert(ret == 0);
    sending_lock = new pthread_spinlock_t;
    pthread_spin_init(sending_lock, PTHREAD_PROCESS_PRIVATE);
}

bool remote_nameserver::operator==(uint32_t ipaddr)
{
    return ip == ipaddr;
}


void remote_nameserver::start_remote()
{
    run.init();
    run.set_data(this);
    pthread_create(&run.thread,
                   nullptr,
                   [](void* param) -> void* {
                       auto pointer = reinterpret_cast<uv_udp_nameserver_runnable*>(param);
                       pointer->start();
                       return nullptr;
                   },
                   &run);
}

//////////////////////////////////////////////////////////////////////

void global_server::cleanup()
{
    int c = 0;
    for (auto& ns : remote_address) {
        pthread_spin_lock(ns.sending_lock);
        const auto& end = ns.sending.end();
        for (auto itor = ns.sending.begin(); itor != end;) {
            if (itor->second->get_response_send()) {
                itor = ns.sending.erase(itor);
                c++;
            } else {
                ++itor;
            }
        }
        pthread_spin_unlock(ns.sending_lock);
    }
    DEBUG("cleaned up {0} item", c);
}

void global_server::add_remote_address(uint32_t ip)
{
    for (auto& ns : remote_address) {
        if (ns == ip) {
            //TODO nameserver exists. Here should have a warning
            INFO("exists.");
            return;
        }
    }

    remote_address.emplace_back(std::move(ip_address(ip)));
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
    struct sockaddr_in addr;
    uv_main_loop = uv_default_loop();

    auto status = uv_timer_init(uv_main_loop, &timer);

    status = uv_timer_init(uv_main_loop, &cleanup_timer);
    utils::check_uv_return_status(status, "timer cleaner init");

    status = uv_udp_init(uv_main_loop, &server_udp);

    utils::check_uv_return_status(status, "uv init");

    const int default_port = 53535;
    const auto default_address = "0.0.0.0";

    status = uv_ip4_addr(default_address, default_port, &addr);
    utils::check_uv_return_status(status, "uv set ipv4 addr");

    status = uv_udp_bind(&server_udp, reinterpret_cast<struct sockaddr*>(&addr), UV_UDP_REUSEADDR);
    utils::check_uv_return_status(status, "bind");

    if (likely(status == 0)) {
        INFO("bind success on {0}:{1}", default_address, default_port);
    }

    status = uv_async_init(uv_main_loop, async_works, [](uv_async_t* work) {
        auto server = reinterpret_cast<global_server*>(work->data);
        uv_timer_stop(&server->cleanup_timer);
        uv_udp_recv_stop(&server->server_udp);
        uv_timer_stop(&server->timer);
        uv_stop(server->uv_main_loop);
        uv_walk(server->uv_main_loop, [](uv_handle_t* t, void*) { uv_close(t, nullptr); }, nullptr);
    });

    status = uv_async_init(uv_main_loop, sending_response_works, [](uv_async_t*) {
        auto& queue = global_server::get_server().response_sending_queue;
        auto lock = global_server::get_server().response_sending_queue_lock;

        pthread_mutex_lock(lock);
        while (queue.size() > 0) {
            auto item = queue.front();
            queue.pop();
            auto send = new uv_udp_send_t;
            send->data = item;
            uv_udp_send(send,
                        &global_server::get_server().server_udp,
                        item->get_buffer(),
                        1,
                        item->get_sock(),
                        [](uv_udp_send_t* send, int) {
                            auto item = reinterpret_cast<found_response*>(send->data);
                            delete item;
                            delete send;
                        });
        }
        pthread_mutex_unlock(lock);
    });

    uv_timer_init(uv_main_loop, &current_time_timer);
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
            remote_address[i].set_index(i);
            remote_address[i].start_remote();
        }
    }
    int reportt = timer_timeout * 1000;
    uv_timer_start(&timer,
                   [](uv_timer_t*) {
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
                   },
                   reportt,
                   reportt);
    uv_timer_start(&cleanup_timer, uvcb_timer_cleaner, 10 * 1000, 10 * 1000);
    uv_udp_recv_start(&server_udp, uvcb_server_incoming_alloc, uvcb_server_incoming_recv);

    const auto& timer_func = [](uv_timer_t* p) {
        static auto ct = reinterpret_cast<utils::atomic_number<time_t>*>(p->data);
        static utils::atomic_int count(0);
        if (count++ % 600 == 0) {
            ct->reset(time(nullptr));
        } else {
            ct->operator++();
        }
    };
    current_time_timer.data = &current_time;
    current_time.reset(time(nullptr));
    uv_timer_start(&current_time_timer, timer_func, 1000, 1000);
}


global_server::~global_server()
{
    for (auto& ns : remote_address) {
        WARN("existing {0}", ns.sending.size());
    }

    if (uv_main_loop != nullptr) {
        uv_loop_close(uv_main_loop);
    }
    if (table != nullptr) {
        delete table;
    }
    pthread_spin_lock(&forward_table_lock);
    forward_table.clear();
    pthread_spin_unlock(&forward_table_lock);
    pthread_spin_destroy(&forward_table_lock);
    pthread_mutex_destroy(response_sending_queue_lock);

    delete response_sending_queue_lock;
    delete async_works;
    delete sending_response_works;
}

global_server::global_server()
    : forward_id(utils::rand_value() & 0xffff),
      server_udp(),
      queue_lock(),
      queue_sem(),
      sending_lock(PTHREAD_MUTEX_INITIALIZER)
{
    response_sending_queue_lock = new pthread_mutex_t;
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
    uv_async_send(async_works);
    for (auto& ns : remote_address) {
        ns.stop_remote();
        ns.run.destroy();
    }
}

void global_server::set_server_log_level(utils::log_level ll)
{
    logging::set_default_level(ll);
}

void global_server::forward_item_all(forward_item_pointer& item)
{
    for (auto& ns : remote_address) {
        send_object* obj = new send_object;
        obj->bufs = item->req->buf;
        obj->bufs_count = 1;
        obj->sock = reinterpret_cast<sockaddr*>(ns.sock);

#ifdef DTRACE_OUTPUT
        string ns_string;
        ns.to_string(ns_string);
        DTRACE("OUT request {0} -> {1}", item->pack->getQuery().getName(), ns_string);
#endif

        ns.send(obj);
        ns.request_forward_count++;
        pthread_spin_lock(ns.sending_lock);
        ns.sending.insert({item->forward_id, item});
        pthread_spin_unlock(ns.sending_lock);
    }
}

void global_server::forward_item_submit(forward_item* item)
{
    increase_forward();
    item->forward_id = forward_id++;
    *reinterpret_cast<uint16_t*>(item->req->buf->base) = item->forward_id;
    forward_item_pointer pointer(item);

    pthread_spin_lock(&forward_table_lock);
    forward_table.insert({item->forward_id, pointer});
    pthread_spin_unlock(&forward_table_lock);

    switch (forward_type) {
        case FT_ALL:
            return forward_item_all(pointer);
        default:
            assert(false);
    }
}

void global_server::send_response(response* resp)
{
    pthread_mutex_lock(response_sending_queue_lock);
    response_sending_queue.emplace(resp);
    pthread_mutex_unlock(response_sending_queue_lock);
    uv_async_send(sending_response_works);
}


void global_server::response_from_remote(uv_buf_t* buf, remote_nameserver* ns)
{
    uint16_t* p = reinterpret_cast<uint16_t*>(buf->base);
    uint16_t forward_id = *p;

#ifdef DTRACE_OUTPUT
    DnsPacket* dpack = DnsPacket::fromDataBuffer(buf);
    string ns_string;
    ns->to_string(ns_string);
    string node_string;
    record_node* node = dpack->generate_record_node();
    if (node != nullptr) {
        node->to_string(node_string);
        DTRACE(
            "IN response from {0}: {1}->{2}", ns_string, dpack->getQuery().getName(), node_string);
    }
    delete node;
    delete dpack;
#endif

    pthread_spin_lock(ns->sending_lock);
    auto ns_forward_item = ns->sending.find(forward_id);
    if (likely(ns_forward_item != ns->sending.end())) {
        ns->sending.erase(forward_id);
    }
    pthread_spin_unlock(ns->sending_lock);

    pthread_spin_lock(&forward_table_lock);
    auto req = forward_table.find(forward_id);
    if (req == forward_table.end()) {
        pthread_spin_unlock(&forward_table_lock);
        utils::free_buffer(buf->base);
        delete buf;
    } else {
        forward_item_pointer pointer = req->second;
        pointer->set_response_send();
        forward_table.erase(req);
        pthread_spin_unlock(&forward_table_lock);
        DnsPacket* pack = DnsPacket::fromDataBuffer(buf);
        pack->parse();
        if (unlikely(pack->getAnswerRRCount() != 0)) {
            record_node* node = pack->generate_record_node();
            cache_add_node(node);
        }
        delete pack;
        forward_response* resp = new forward_response(pointer, buf);
        send_response(resp);
    }
}

void global_server::cache_add_node(record_node* node)
{
    if (table != nullptr) {
        table->put(node);
    }
}

/////// callbacks

void uvcb_incoming_request_worker(uv_work_t* work)
{
    auto& server = global_server::get_server();
    auto& table = server.get_hashtable();

    server.increase_request();
    request* req = reinterpret_cast<request*>(work->data);

    DnsPacket* pack =
        DnsPacket::fromDataBuffer(reinterpret_cast<uint8_t*>(req->buf->base), req->nsize);

    pack->parse();
    auto name = pack->getQuery().getName();
    if (unlikely(strcmp(name, "stop.dnsserver.ok") == 0)) {
        // TODO: stop server code
        delete req;
        delete pack;
        work->data = nullptr;
    } else {
        auto id = pack->getQueryID();
        record_node* found = table.get(name);
        request_pointer pointer(req);
        if (found == nullptr) {
            DTRACE("IN request:  ID #{0:x} -> {1}. NOT Found", id, name);
            forward_item* fitem = new forward_item(pack, pointer);
            server.forward_item_submit(fitem);
        } else {
            string text;
            found->to_string(text);
            DTRACE("IN request:  ID #{0:x} -> {1} : {2}", id, name, text);
            DnsPacket* ret = DnsPacket::build_response_with_records(pack, found);
            found_response* fitem = new found_response(ret, pointer);
            server.send_response(fitem);
            delete pack;
        }
    }
}

void uvcb_remote_recv(
    uv_udp_t* udp, ssize_t nread, const uv_buf_t* buf, const sockaddr* sock, unsigned int)
{
    if (nread <= 0) {
        if (sock == nullptr) {
        } else {
            // recv empty udp diagram from remote nameserver, just ignore
        }
        utils::free_buffer(buf->base);
    } else {
        auto ns = reinterpret_cast<remote_nameserver*>(udp->data);
        uv_buf_t* nbuf = new uv_buf_t;
        nbuf->base = buf->base;
        nbuf->len = nread;
        global_server::get_server().response_from_remote(nbuf, ns);
    }
}

void uvcb_remote_nameserver_send_complete(uv_udp_send_t* send, int flag)
{
    if (unlikely(flag < 0)) {
        WARN("send error {0}", uv_err_name(flag));
    }

    auto sending = reinterpret_cast<uv_udp_sending*>(send->data);
    delete sending->obj;
    delete sending;
    delete send;
}

utils::atomic_int uv_udp_nameserver_runnable::count;

void uvcb_async_remote_send(uv_async_t* send)
{
    auto sending_obj = reinterpret_cast<uv_udp_nameserver_runnable*>(send->data);
    pthread_mutex_lock(sending_obj->lock);
    while (sending_obj->sending_queue.size() > 0) {
        auto i = sending_obj->sending_queue.front();
        sending_obj->sending_queue.pop();
        uv_udp_send_t* sending = new uv_udp_send_t;
        sending->data = i;
        auto flag = uv_udp_send(sending,
                                i->handle,
                                i->obj->bufs,
                                i->obj->bufs_count,
                                i->obj->sock,
                                uvcb_remote_nameserver_send_complete);
        if (unlikely(flag < 0)) {
            ERROR("send failed: {0}", uv_err_name(flag));
        }
    }
    pthread_mutex_unlock(sending_obj->lock);
}

void uvcb_timer_cleaner(uv_timer_t*)
{
    global_server::get_server().cleanup();
}
