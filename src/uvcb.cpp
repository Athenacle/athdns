/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// uvcb.cpp: callbacks for libuv

#include "athdns.h"
#include "logging.h"
#include "objects.h"
#include "server.h"

using namespace objects;
using namespace dns;

void uvcb_server_incoming_alloc(uv_handle_t*, size_t, uv_buf_t* buf)
{
    buf->base = utils::get_buffer();
    buf->len = recv_buffer_size;
}

void uvcb_server_incoming_recv(
    uv_udp_t* udp, ssize_t nread, const uv_buf_t* buf, const sockaddr* addr, unsigned int flag)
{
    static auto loop = global_server::get_server().get_main_loop();

    if (unlikely((flag & UV_UDP_PARTIAL) == UV_UDP_PARTIAL)) {
        ERROR("udp received partical");
        utils::free_buffer(buf->base);
        return;
    }

    if (unlikely(nread < 0)) {
        ERROR("transmission error.");
        utils::free_buffer(buf->base);
        return;
    }
    if (unlikely(nread == 0)) {
        /* Note nread == 0 and addr == NULL ==> there is nothing to read,
         *      nread == 0 and addr != NULL ==> an empty UDP packet is received.
        */
        if (addr == nullptr) {
            // an empty datagram was received
        } else {
            WARN("an empty datagram was received, skip this");
        }
        utils::free_buffer(buf->base);
        return;
    }

    auto req = new objects::request(buf, nread, addr, udp);

    uv_work_t* work = new uv_work_t;
    work->data = req;

    uv_queue_work(loop, work, uvcb_incoming_request_worker, [](uv_work_t* work, int) {
        if (unlikely(work->data == nullptr)) {
            //NOTE: when STOP string "stop.dnsserver.ok" received, work->data will be
            //      set to nullptr. Please refer to `uvcb_incoming_request_worker'
            global_server::get_server().do_stop();
        }
        delete work;
    });
}

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

void uvcb_remote_udp_recv(
    uv_udp_t* udp, ssize_t nread, const uv_buf_t* buf, const sockaddr* sock, unsigned int)
{
    if (nread <= 0) {
        if (sock == nullptr) {
        } else {
            // recv empty udp diagram from remote nameserver, just ignore
        }
        utils::free_buffer(buf->base);
    } else {
        auto ns = reinterpret_cast<remote::udp_nameserver*>(udp->data);
        uv_buf_t* nbuf = global_server::get_server().new_uv_buf_t();
        nbuf->base = buf->base;
        nbuf->len = nread;
        global_server::get_server().response_from_remote(nbuf, ns);
    }
}
