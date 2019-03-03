
#include "athdns.h"
#include "logging.h"
#include "objects.h"
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

    auto req = new objects::request(buf, nread, addr);

    uv_work_t* work = new uv_work_t;
    work->data = req;

    uv_queue_work(loop, work, uvcb_incoming_request_worker, [](uv_work_t* work, int) {
        if (unlikely(work->data == nullptr)) {
            global_server::get_server().do_stop();
        }
        delete work;
    });
}

int main(int argc, CH* const argv[])
{
    logging::init_logging();

    utils::config_system(argc, argv);
    utils::init_buffer_pool(1024);

    auto& server = global_server::get_server();

    server.init_server();
    server.start_server_loop();

    global_server::destroy_server();
    utils::destroy_buffer();
    logging::destroy_logger();

    return 0;
}
