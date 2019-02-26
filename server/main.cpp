
#include "dns.h"
#include "dnsserver.h"
#include "server.h"


using namespace dns;

void atexit_handler();

void uvcb_server_incoming_alloc(uv_handle_t*, size_t, uv_buf_t* buf)
{
    buf->base = utils::get_buffer();
    buf->len = recv_buffer_size;
}

void uvcb_server_incoming_recv(
    uv_udp_t*, ssize_t nread, const uv_buf_t* buf, const sockaddr* addr, unsigned int flag)
{
    static auto& server = global_server::get_server();
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

    auto req = new request(buf, nread, addr);

    uv_work_t* work = new uv_work_t;
    work->data = req;

    uv_queue_work(loop, work, uvcb_incoming_request_worker, uvcb_incoming_request_worker_complete);
    server.increase_request();
}

void uvcb_timer_reporter(uv_timer_t*)
{
    static auto& server = global_server::get_server();
    int forward = server.get_total_forward_cound();
    int total = server.get_total_request();
    auto hit = total - forward;
    INFO(
        "Report: Incoming Request {0}, hashtable hit {1}, missing rate {2} forward count {3}, "
        "hashtable saved {4}, memory usage {5} kB ",
        total,
        total - forward,
        (hit * 1.0) / total,
        forward,
        server.get_hashtable_size(),
        0);
}

void atexit_handler()
{
    global_server::destroy_server();
    utils::destroy_buffer();
}


int main(int argc, CH* const argv[])
{
    logging::init_logging();

    utils::config_system(argc, argv);
    utils::init_buffer_pool(1024);

    atexit(atexit_handler);
    auto& server = global_server::get_server();

    server.init_server();
    server.start_server_loop();

    return 0;
}
