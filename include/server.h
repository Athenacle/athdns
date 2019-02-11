
#pragma once

#ifndef SERVER_H
#define SERVER_H


#include "dns.h"
#include "dnsserver.h"
#include "hash.h"
#include "logging.h"

#include <pthread.h>
#include <semaphore.h>
#include <queue>


void *work_thread_fn(void *);


class global_server
{
    using hash_table_type     = hash::hash_table<const char *, hash::hash_entry<const char *> >;
    using static_address_type = std::tuple<string, uint32_t>;

    std::vector<ip_address> remote_address;
    std::vector<static_address_type> *static_address;
    std::queue<dns::DnsPacket *> requests;

    hash_table_type *hash;

    int total_request_count;
    int default_ttl;
    size_t cache_count;

    string log_file;
    bool timeout_requery;
    bool parallel_query;

    uv_loop_t *uv_main_loop;
    uv_udp_t server_socket;

    pthread_t working_thread;
    pthread_spinlock_t queue_lock;
    sem_t queue_sem;


    global_server(const global_server &) = delete;
    void operator=(const global_server &) = delete;

    global_server() : server_socket(), working_thread(), queue_lock(), queue_sem()
    {
        total_request_count = 0;
        timeout_requery     = false;
        parallel_query      = false;
        default_ttl         = 256;
        cache_count         = 1000;
        log_file            = "";
        uv_main_loop        = nullptr;
        hash                = nullptr;
        static_address      = nullptr;

        pthread_spin_init(&queue_lock, PTHREAD_PROCESS_PRIVATE);
        sem_init(&queue_sem, 0, 0);
    }

    ~global_server();

    static global_server *server_instance;

public:
    pthread_spinlock_t *get_spinlock()
    {
        return &queue_lock;
    }

    hash_table_type &get_hashtable()
    {
        return *hash;
    }


    sem_t *get_semaphore()
    {
        return &queue_sem;
    }

    std::queue<dns::DnsPacket *> &get_queue()
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
};


#endif
