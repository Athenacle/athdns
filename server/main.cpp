
#include "dns.h"
#include "dnsserver.h"
#include "server.h"

using namespace dns;

void atexit_handler();

void uv_handler_on_alloc(uv_handle_t*, size_t, uv_buf_t* buf)
{
    const size_t suggest = 512;
    buf->base            = reinterpret_cast<char*>(malloc(suggest * sizeof(char)));
    buf->len             = suggest;
}

void uv_handler_on_recv(
    uv_udp_t*, ssize_t nread, const uv_buf_t* buf, const sockaddr* addr, unsigned int)
{
    static auto& server     = global_server::get_server();
    static auto& rqueue     = server.get_queue();
    static auto* queue_lock = server.get_spinlock();
    static auto* queue_sem  = server.get_semaphore();

    if (addr == nullptr && nread == 0) {
        free(buf->base);
        return;
    }

    auto packet   = DnsPacket::fromDataBuffer(reinterpret_cast<uint8_t*>(buf->base),
                                            static_cast<uint32_t>(nread));
    auto new_addr = utils::make(addr);
    packet->parse();
    free(buf->base);
    pthread_spin_lock(queue_lock);
    rqueue.emplace(std::make_tuple(packet, new_addr));
    sem_post(queue_sem);
    pthread_spin_unlock(queue_lock);
    server.increase_request();
}

void delete_timer_worker(uv_timer_t*)
{
    static auto& server = global_server::get_server();
    static int timeout  = server.cleanup_timer_timeout;
    auto& dqueue        = server.delete_queue;
    auto dl             = &server.delete_queue_lock;
    auto timestamp      = time(nullptr) + timeout;

    pthread_spin_lock(dl);
    while (true && dqueue.size() > 0) {
        auto& front = dqueue.front();
        auto& t     = std::get<0>(front);
        if (t > timestamp) {
            dqueue.pop();
            global_server::free_delete_item(front);
        } else {
            break;
        }
    }
    pthread_spin_unlock(dl);
}

void uv_timer_handler(uv_timer_t*)
{
    static auto& server   = global_server::get_server();
    static auto total_mem = uv_get_total_memory();
    int forward           = server.get_total_forward_cound();
    int total             = server.get_total_request();
    auto hit              = total - forward;
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
