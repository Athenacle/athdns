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
            TRACE("an empty datagram was received, skip this");
        }
        utils::free_buffer(buf->base);
        return;
    }

    static auto& server = global_server::get_server();
    static auto& table = server.get_hashtable();

    dns::dns_parse_status status;
    DnsPacket* pack = DnsPacket::fromDataBuffer(buf, status);
    if (status == dns_parse_status::request_ok) {
        assert(pack != nullptr);
        auto req = new objects::request(buf, nread, addr, udp, pack);
        server.increase_request();

        auto name = pack->getQuery().getName();
        if (unlikely(strcmp(name, "stop.dnsserver.ok") == 0)) {
            delete req;
            global_server::get_server().do_stop();
        } else {
            auto id = pack->getQueryID();
            record_node* found = table.get(name);
            if (found == nullptr) {
                TRACE("IN request: ID #{0:x} -> {1}.", id, name);
                forward_response* fitem = new forward_response(req);
                server.forward_item_submit(fitem);
            } else {
                string text;
                found->to_string(text);
                TRACE("IN request: ID #{0:x} -> {1} : {2} (cached)", id, name, text);
                DnsPacket* ret = DnsPacket::build_response_with_records(pack, found);
                uv_buf_t* buf = global_server::get_server().new_uv_buf_t();
                buf->base = utils::get_buffer();
                buf->len = ret->get_size();
                memmove(buf->base, ret->get_data(), ret->get_size());
                uv_udp_send_t* sent = global_server::get_server().new_uv_udp_send_t();
                sent->data = buf;
                uv_udp_send(sent, udp, buf, 1, addr, [](uv_udp_send_t* sent, int f) {
                    auto buf = reinterpret_cast<uv_buf_t*>(sent->data);
                    if (unlikely(f < 0)) {
                        DnsPacket* pack = DnsPacket::fromDataBuffer(buf);
                        pack->parse();
                        TRACE("sending failed for {0}: {1}",
                              pack->getQuery().getName(),
                              uv_strerror(f));
                        delete pack;
                    }
                    global_server::get_server().delete_uv_buf_t(buf);
                    global_server::get_server().delete_uv_udp_send_t(sent);
                });
                delete ret;
            }
        }
    } else {
        TRACE("malformed packet received");
        utils::free_buffer(buf->base);
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
