
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

void *work_thread_fn(void *);

void delete_timer_worker(uv_timer_t *);


class global_server
{
    friend void delete_timer_worker(uv_timer_t *);

    const int cleanup_timer_timeout = 10;

    using static_address_type = std::tuple<string, uint32_t>;
    using queue_item          = std::tuple<dns::DnsPacket *, const sockaddr *>;

    using delete_item = std::tuple<time_t, dns::DnsPacket *, uv_buf_t *, const sockaddr *>;

    std::vector<ip_address> remote_address;
    std::vector<static_address_type> *static_address;
    std::queue<queue_item> requests;
    std::queue<delete_item> delete_queue;

    hash::hashtable *table;

    int total_request_count;
    int total_request_forward_count;

    int default_ttl;
    int timer_timeout;

    size_t cache_count;

    string log_file;
    bool timeout_requery;
    bool parallel_query;

    uv_loop_t *uv_main_loop;
    uv_udp_t server_socket;

    uv_timer_t timer;
    uv_timer_t delete_timer;

    pthread_t working_thread;

    pthread_spinlock_t queue_lock;
    pthread_spinlock_t delete_queue_lock;

    sem_t queue_sem;

    global_server(const global_server &) = delete;
    void operator=(const global_server &) = delete;

    global_server()
        : server_socket(), working_thread(), queue_lock(), delete_queue_lock(), queue_sem()
    {
        total_request_count         = 0;
        total_request_forward_count = 0;
        timeout_requery             = false;
        parallel_query              = false;
        default_ttl                 = 256;
        cache_count                 = 3000;
        log_file                    = "";
        uv_main_loop                = nullptr;
        static_address              = nullptr;
        timer_timeout               = 5;

        pthread_spin_init(&queue_lock, PTHREAD_PROCESS_PRIVATE);
        pthread_spin_init(&delete_queue_lock, PTHREAD_PROCESS_PRIVATE);
        sem_init(&queue_sem, 0, 0);
        table = nullptr;
    }

    ~global_server();

    static global_server *server_instance;

    static void free_delete_item(delete_item &);


public:
    pthread_spinlock_t *get_delete_lock()
    {
        return &delete_queue_lock;
    }

    std::queue<delete_item> &get_delete_queue()
    {
        return delete_queue;
    }


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

    int get_total_request() const
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

    const std::vector<ip_address> get_remote_server() const
    {
        return remote_address;
    }

    void init_server_loop();

    void init_server();


    void start_server_loop()
    {
        uv_run(uv_main_loop, UV_RUN_DEFAULT);
    }

    void do_stop();
};


#endif
