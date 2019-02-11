
#include "dns.h"
#include "dnsserver.h"
#include "server.h"

#include "glog/logging.h"

using namespace dns;

void atexit_handler();

void uv_handler_on_alloc(uv_handle_t*, size_t, uv_buf_t* buf)
{
    const size_t suggest = 256;
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
        return;
    }

    auto packet = DnsPacket::fromDataBuffer(reinterpret_cast<uint8_t*>(buf->base),
                                            static_cast<uint32_t>(nread));
    packet->parse();
    free(buf->base);
    pthread_spin_lock(queue_lock);
    rqueue.emplace(packet);
    sem_post(queue_sem);
    pthread_spin_unlock(queue_lock);

    LOG(WARNING) << "RECV CALLED.";
}

void atexit_handler()
{
    global_server::destroy_server();
}


int main(int argc, CH* const argv[])
{
#ifndef NDEBUG
    FLAGS_logtostderr      = 1;
    FLAGS_colorlogtostderr = 1;
#endif

    google::InitGoogleLogging(argv[0]);
    utils::config_system(argc, argv);

    auto& server = global_server::get_server();
    server.init_server();
    server.start_server_loop();

    atexit(atexit_handler);
    return 0;
}
