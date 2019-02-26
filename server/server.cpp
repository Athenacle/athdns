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
using namespace dns;

global_server* global_server::server_instance = nullptr;


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
    utils::free_buffer(buf->base);
    delete buf;
}

// forward_item

forward_item::forward_item(DnsPacket* packet, const request_pointer& rp) : req(rp), pack(packet)
{
    insert_time = time(nullptr);
    original_query_id = *reinterpret_cast<uint16_t*>(rp->buf->base);
    pthread_spin_init(&_lock, PTHREAD_PROCESS_PRIVATE);
}

forward_item::~forward_item()
{
    pthread_spin_destroy(&_lock);
    delete pack;
}

// remote nameserver

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

    std::swap(run, ns.run);
    std::swap(request_forward_count, ns.request_forward_count);
    std::swap(response_count, ns.response_count);

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

// delete_item
delete_item::delete_item(DnsPacket* package, const request_pointer& rp) : req(rp), pack(package) {}

delete_item::~delete_item()
{
    delete pack;
    delete buf;
}

// found_reponse_item

found_response_item::found_response_item(DnsPacket* pack, request* rq) : packet(pack), req(rq)
{
    buf = new uv_buf_t;
    buf->base = reinterpret_cast<char*>(pack->get_data());
    buf->len = pack->get_size();
}

found_response_item::~found_response_item()
{
    delete buf;
    delete packet;
    delete req;
}

//////////////////////////////////////////////////////////////////////

void global_server::cleanup()
{
    time_t current_t = time(nullptr);
    time_t clean_time = current_t - 10;
    int c = 0;
    for (auto& ns : remote_address) {
        pthread_spin_lock(ns.sending_lock);
        for (auto& p : ns.sending) {
            if (p.second->insert_time < clean_time) {
                ns.sending.erase(p.first);
                c++;
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

    status = uv_timer_start(&cleanup_timer, uvcb_timer_cleaner, 10 * 1000, 10 * 1000);

    check(status, "cleaner timer start");

    status = uv_udp_init(uv_main_loop, &server_socket);

    check(status, "uv init");

    const int default_port = 53535;
    const auto default_address = "0.0.0.0";

    status = uv_ip4_addr(default_address, default_port, &addr);
    check(status, "uv set ipv4 addr");
    status =
        uv_udp_bind(&server_socket, reinterpret_cast<struct sockaddr*>(&addr), UV_UDP_REUSEADDR);
    check(status, "bind");

    if (likely(status == 0)) {
        INFO("bind success on {0}:{1}", default_address, default_port);
    }

    status =
        uv_udp_recv_start(&server_socket, uvcb_server_incoming_alloc, uvcb_server_incoming_recv);

    check(status, "recv start");

    status = uv_async_init(uv_main_loop, async_works, uvcb_async_stop_loop);

    status = uv_async_init(uv_main_loop, sending_works, uvcb_async_response_send);

    status = uv_async_init(uv_main_loop, sending_response_works, uvcb_async_remote_response_send);
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
    delete async_works;
    delete sending_works;
    delete sending_response_works;
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
        ns.send(obj);
        ns.request_forward_count++;
        ns.sending[item->forward_id] = item;
    }
}

void global_server::forward_item_submit(forward_item* item)
{
    increase_forward();
    item->insert_time = time(nullptr);
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

void global_server::send_response(found_response_item* item)
{
    uv_udp_send_t* send = new uv_udp_send_t;
    send->data = item;
    pthread_mutex_lock(&sending_lock);
    sending_works->data = send;
    uv_async_send(sending_works);
}

void global_server::send_response(forward_response* resp)
{
    uv_udp_send_t* send = new uv_udp_send_t;
    send->data = resp;
    pthread_mutex_lock(&sending_lock);
    sending_response_works->data = send;
    uv_async_send(sending_response_works);
}

void global_server::response_from_remote(uv_buf_t* buf, remote_nameserver* ns)
{
    uint16_t* p = reinterpret_cast<uint16_t*>(buf->base);
    uint16_t forward_id = *p;

    auto ns_forward_item = ns->sending.find(forward_id);
    if (likely(ns_forward_item != ns->sending.end())) {
        ns->sending.erase(forward_id);
    } else {
        WARN("assert(ns_forward_item != ns->sending.end())");
    }

    pthread_spin_lock(&forward_table_lock);
    auto req = forward_table.find(forward_id);
    if (req == forward_table.end()) {
        pthread_spin_unlock(&forward_table_lock);
        utils::free_buffer(buf->base);
        delete buf;
    } else {
        forward_item_pointer pointer = req->second;
        forward_table.erase(req);
        pthread_spin_unlock(&forward_table_lock);
        *p = pointer->original_query_id;
        forward_response* resp = new forward_response(pointer, buf);
        send_response(resp);
    }
}

////////////////////////////////////////////////////////////////////////////////////////
// void uvcb_incoming_request_response_send_complete(uv_udp_send_t* req, int status)  //
// {                                                                                  //
//     assert(0);                                                                     //
//     found_response_item* item = reinterpret_cast<found_response_item*>(req->data); //
//     if (unlikely(status < 0)) {                                                    //
//         ERROR("DNS reply send  failed: {0}", uv_strerror(status));                 //
//     }                                                                              //
//     delete item;                                                                   //
//     delete req;                                                                    //
// }                                                                                  //
////////////////////////////////////////////////////////////////////////////////////////

/////// callbacks

void uvcb_incoming_request_worker(uv_work_t* work)
{
    static auto& server = global_server::get_server();
    static auto& table = server.get_hashtable();

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
        if (found == nullptr) {
            request_pointer pointer(req);
            DDEBUG("Input DNS Request:  ID #{0:x} -> {1}. NOT Found", id, name);
            forward_item* fitem = new forward_item(pack, pointer);
            server.forward_item_submit(fitem);
        } else {
            string text;
            found->to_string(text);
            DEBUG("Input DNS Request:  ID #{0:x} -> {1} : {2}", id, name, text);
            DnsPacket* ret = DnsPacket::build_response_with_records(pack, found);
            found_response_item* fitem = new found_response_item(ret, req);
            server.send_response(fitem);
            delete pack;
        }
    }
}


void uvcb_incoming_request_worker_complete(uv_work_t* work, int)
{
    if (work->data == nullptr) {
        global_server::get_server().do_stop();
    }
    delete work;
}

void uvcb_async_stop_loop(uv_async_t* work)
{
    auto server = reinterpret_cast<global_server*>(work->data);
    uv_timer_stop(&server->cleanup_timer);
    uv_udp_recv_stop(&server->server_socket);
    uv_timer_stop(&server->timer);
    uv_stop(server->uv_main_loop);
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

void* remote_nameserver_thread(void* run)
{
    auto pointer = reinterpret_cast<uv_udp_nameserver_runnable*>(run);
    pointer->start();
    return nullptr;
}

void uvcb_async_remote_stop_loop(uv_async_t* work)
{
    auto pointer = reinterpret_cast<uv_udp_nameserver_runnable*>(work->data);
    uv_udp_recv_stop(pointer->udp);
    uv_stop(pointer->loop);
}

void uvcb_async_response_send(uv_async_t* work)
{
    auto send = reinterpret_cast<uv_udp_send_t*>(work->data);
    auto item = reinterpret_cast<found_response_item*>(send->data);
    uv_udp_send(send,
                &global_server::get_server().server_socket,
                item->get_buffer(),
                1,
                item->get_sock(),
                uvcb_response_send_complete);
}

void uvcb_response_send_complete(uv_udp_send_t* send, int)
{
    static pthread_mutex_t* mutex = &global_server::get_server().sending_lock;
    pthread_mutex_unlock(mutex);
    auto item = reinterpret_cast<found_response_item*>(send->data);
    delete item;
    delete send;
}

void uvcb_async_remote_response_send(uv_async_t* async)
{
    auto send = reinterpret_cast<uv_udp_send_t*>(async->data);
    auto item = reinterpret_cast<forward_response*>(send->data);
    uv_udp_send(send,
                global_server::get_server().get_server_socket(),
                item->buf,
                1,
                item->pointer->req->sock,
                uvcb_remote_response_send_complete);
}

void uvcb_remote_response_send_complete(uv_udp_send_t* send, int)
{
    static pthread_mutex_t* mutex = &global_server::get_server().sending_lock;
    pthread_mutex_unlock(mutex);
    auto item = reinterpret_cast<forward_response*>(send->data);
    delete item;
    delete send;
}

void uvcb_remote_nameserver_send_complete(uv_udp_send_t* send, int flag)
{
    if (unlikely(flag < 0)) {
        WARN("send error {0}", uv_err_name(flag));
    }
    auto sending_obj = reinterpret_cast<uv_udp_sending*>(send->data);
    delete sending_obj->obj;
    delete sending_obj;
    delete send;
}

utils::atomic_int uv_udp_nameserver_runnable::count;

void uvcb_async_remote_send(uv_async_t* send)
{
    auto sending_obj = reinterpret_cast<uv_udp_sending*>(send->data);
    pthread_spin_unlock(sending_obj->lock);
    uv_udp_send_t* sending = new uv_udp_send_t;
    sending->data = sending_obj;
    auto flag = uv_udp_send(sending,
                            sending_obj->handle,
                            sending_obj->obj->bufs,
                            sending_obj->obj->bufs_count,
                            sending_obj->obj->sock,
                            uvcb_remote_nameserver_send_complete);
    if (unlikely(flag < 0)) {
        ERROR("send failed: {0}", uv_err_name(flag));
    }
}

void uvcb_timer_cleaner(uv_timer_t*)
{
    global_server::get_server().cleanup();
}
