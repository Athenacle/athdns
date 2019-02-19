
#pragma once

#ifndef SERVER_H
#define SERVER_H


#include "dns.h"
#include "dnsserver.h"
#include "hash.h"
#include "logging.h"

#include <pthread.h>
#include <semaphore.h>
#include <sys/prctl.h>
#include <queue>
#include <unordered_map>

void *work_thread_fn(void *);

void uvcb_remote_nameserver_forward(uv_work_t *);

void uvcb_remote_nameserver_forward_complete(uv_work_t *, int);

void uvcb_remote_nameserver_sending_complete(uv_udp_send_t *, int);

void uvcb_remote_nameserver_forward_reading(
    uv_udp_t *, ssize_t, const uv_buf_t *, const sockaddr *, unsigned int);

void uv_forward_response_sender(uv_udp_send_t *, int);


struct delete_item {
    time_t t;
    dns::DnsPacket *dns_packet;
    uv_buf_t *buf;
    const sockaddr *addr;

    delete_item(time_t tt, dns::DnsPacket *p, uv_buf_t *b, const sockaddr *a)
        : t(tt), dns_packet(p), buf(b), addr(a)
    {
    }

    void do_delete()
    {
        delete dns_packet;
        utils::destroy(buf);
        utils::destroy(addr);
#ifndef NDEBUG
        dns_packet = nullptr;
        buf = nullptr;
        addr = nullptr;
#endif
    }

    ~delete_item()
    {
        assert(dns_packet == nullptr);
        assert(buf == nullptr);
        assert(addr == nullptr);
    }

private:
    delete_item() = delete;
    delete_item(const delete_item &) = delete;
};

struct incoming_request {
    uv_buf_t *buf;
    ssize_t nsize;
    sockaddr *sock;

    incoming_request(uv_buf_t *, ssize_t, sockaddr *);
    ~incoming_request();
};


struct remote_nameserver {
    int index;
    int port;
    sockaddr_in *sock;
    ip_address ip;
    uv_udp_t *udp_handle;

    utils::atomic_int request_forward_count;
    utils::atomic_int response_count;

    remote_nameserver(remote_nameserver &&);

    remote_nameserver(const ip_address &&, int = 53);
    remote_nameserver(uint32_t, int = 53);
    ~remote_nameserver();

    bool operator==(const ip_address &);
    bool operator==(uint32_t);

    void swap(const remote_nameserver &);


    int get_index() const
    {
        return index;
    }

    void set_index(int i)
    {
        index = i;
    }

    operator const sockaddr *() const
    {
        return reinterpret_cast<const sockaddr *>(sock);
    }

    const sockaddr *get_sockaddr()
    {
        return reinterpret_cast<const sockaddr *>(sock);
    }

    remote_nameserver *get_address()
    {
        return this;
    }

    void init_udp_handle(uv_loop_t *);

    void start_recv()
    {
        uv_udp_recv_start(
            udp_handle, uvcb_server_incoming_alloc, uvcb_remote_nameserver_forward_reading);
    }

    void stop_recv()
    {
        uv_udp_recv_stop(udp_handle);
    }
};


struct forward_item {
    dns::DnsPacket *packet;
    uv_buf_t *buf;
    const sockaddr *req_sock;
    remote_nameserver *ns;
    uv_buf_t *resp_buf;
    time_t insert_time;
    uint16_t forward_id;
    uint16_t original_query_id;
    pthread_spinlock_t _lock;

    void destroy();

    void lock()
    {
        pthread_spin_lock(&_lock);
    }

    void unlock()
    {
        pthread_spin_unlock(&_lock);
    }


    forward_item()
    {
        pthread_spin_init(&_lock, PTHREAD_PROCESS_PRIVATE);
    }
    ~forward_item()
    {
        pthread_spin_destroy(&_lock);
    }
};

class global_server
{
    friend void delete_timer_worker(uv_timer_t *);

    using static_address_type = std::tuple<string, uint32_t>;
    using queue_item = std::tuple<uv_buf_t *, const sockaddr *, ssize_t>;

    std::vector<remote_nameserver> remote_address;
    std::vector<static_address_type> *static_address;
    std::queue<queue_item> requests;
    std::unordered_map<uint16_t, forward_item *> forward_table;

    utils::atomic_int forward_id;

    hash::hashtable *table;

    utils::atomic_int total_request_count;
    utils::atomic_int total_request_forward_count;

    int default_ttl;
    int timer_timeout;

    size_t cache_count;

    string log_file;
    bool timeout_requery;
    bool parallel_query;

    uv_loop_t *uv_main_loop;
    uv_udp_t server_socket;

    uv_timer_t timer;

    pthread_t working_thread;

    pthread_spinlock_t queue_lock;
    pthread_spinlock_t forward_table_lock;

    sem_t queue_sem;

    int forward_type;

    global_server(const global_server &) = delete;
    void operator=(const global_server &) = delete;

    global_server()
        : forward_id(utils::rand_value() & 0xff),
          server_socket(),
          working_thread(),
          queue_lock(),
          queue_sem()
    {
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

        sem_init(&queue_sem, 0, 0);
        table = nullptr;
    }

    ~global_server();

    static global_server *server_instance;

    void forward_item_all(forward_item *);

    void forward_single_item(forward_item *, remote_nameserver &);

public:
    void forward_item_complete(ssize_t, const uv_buf_t *);

    void forward_item_submit(forward_item *);

    uv_udp_t *get_server_socket()
    {
        return &server_socket;
    }


    void increase_request()
    {
        total_request_count++;
    }

    void increase_forward()
    {
        total_request_forward_count++;
    }

    int get_total_forward_cound()
    {
        return total_request_forward_count;
    }

    int get_total_request()
    {
        return total_request_count;
    }

    record_node *get_last_request()
    {
        return table->get_last();
    }

    int get_hashtable_size() const
    {
        return table->get_saved();
    }


    hash::hashtable &get_hashtable()
    {
        return *table;
    }


    pthread_spinlock_t *get_spinlock()
    {
        return &queue_lock;
    }

    sem_t *get_semaphore()
    {
        return &queue_sem;
    }

    std::queue<queue_item> &get_queue()
    {
        return requests;
    }


    static void destroy_server()
    {
        if (server_instance != nullptr) {
            delete server_instance;
        }
    }

    static global_server &get_server()
    {
        if (server_instance == nullptr)
            server_instance = new global_server;

        return *server_instance;
    }

    bool remote_address_exist(const ip_address &) const;

    void set_parallel_query(bool pq)
    {
        parallel_query = pq;
    }

    void set_report_timeout(int to)
    {
        timer_timeout = to;
    }

    void set_timeout_requery(bool re)
    {
        timeout_requery = re;
    }

    void set_default_ttl(int ttl)
    {
        default_ttl = ttl;
    }

    void set_cache_size(size_t size)
    {
        cache_count = size;
    }

    void add_static_ip(const string &, uint32_t);
    void set_static_ip(const string &, uint32_t);

    void set_log_file(const CH *);

    void add_remote_address(const ip_address &);
    void add_remote_address(uint32_t);

    void set_server_log_level(utils::log_level);

    const std::vector<remote_nameserver> &get_remote_server() const
    {
        return remote_address;
    }

    void init_server_loop();

    void init_server();


    void start_server_loop()
    {
        uv_run(uv_main_loop, UV_RUN_DEFAULT);
        pthread_join(working_thread, nullptr);
    }

    void do_stop();
};


#endif
