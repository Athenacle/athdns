
#include "dns.h"
#include "dnsserver.h"
#include "server.h"

using namespace dns;

void atexit_handler();

void uvcb_server_incoming_alloc(uv_handle_t*, size_t, uv_buf_t* buf)
{
    const size_t suggest = 512;
    buf->base = reinterpret_cast<char*>(malloc(suggest * sizeof(char)));
    buf->len = suggest;
}

void uvcb_server_incoming_recv(
    uv_udp_t*, ssize_t nread, const uv_buf_t* buf, const sockaddr* addr, unsigned int)
{
    static auto& server = global_server::get_server();
    static auto& rqueue = server.get_queue();
    static auto* queue_lock = server.get_spinlock();
    static auto* queue_sem = server.get_semaphore();

    if (addr == nullptr && nread == 0) {
        free(buf->base);
        return;
    }

    auto new_addr = utils::make(addr);
    auto new_buf = utils::make(buf);
    new_buf->len = nread;

    pthread_spin_lock(queue_lock);
    rqueue.emplace(std::make_tuple(new_buf, new_addr, nread));
    pthread_spin_unlock(queue_lock);
    sem_post(queue_sem);
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
}


int main(int argc, CH* const argv[])
{
    logging::init_logging();
    utils::config_system(argc, argv);
    auto& server = global_server::get_server();
    atexit(atexit_handler);

    server.init_server();
    server.start_server_loop();

    return 0;
}
