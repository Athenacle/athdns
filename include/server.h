/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// server.h: global_server file header

#ifndef SERVER_H
#define SERVER_H

#include "athdns.h"
#include "dns.h"
#include "hash.h"
#include "objects.h"
#include "remote.h"

#include <pthread.h>
#include <semaphore.h>
#include <sys/prctl.h>

#include <map>
#include <memory>
#include <queue>
#include <unordered_map>

using remote::remote_nameserver;

void uvcb_incoming_request_worker(uv_work_t *);

void uvcb_incoming_request_response_send_complete(uv_udp_send_t *, int);

void uvcb_async_response_send(uv_async_t *);

void uvcb_async_remote_response_send(uv_async_t *);

void uvcb_timer_cleaner(uv_timer_t *);

class global_server
{
    friend void delete_timer_worker(uv_timer_t *);
    friend void uvcb_async_stop_loop(uv_async_t *);
    friend void uvcb_async_response_send(uv_async_t *);
    friend void uvcb_timer_cleaner(uv_timer_t *);
    friend void uvcb_async_remote_response_send(uv_async_t *async);

    using static_address_type = std::tuple<string, uint32_t>;
    using queue_item = std::tuple<uv_buf_t *, const sockaddr *, ssize_t>;

    std::vector<remote_nameserver *> remote_address;
    std::vector<static_address_type> *static_address;

    std::unordered_map<uint16_t, objects::forward_item_pointer> forward_table;

    std::queue<objects::response *> response_sending_queue;

    pthread_mutex_t *response_sending_queue_lock;

    utils::atomic_int forward_id;

    hash::hashtable *table;

    utils::atomic_int total_request_count;
    utils::atomic_int total_request_forward_count;
    utils::atomic_number<time_t> current_time;

    int default_ttl;
    int timer_timeout;

    size_t cache_count;

    string log_file;
    bool timeout_requery;
    bool parallel_query;

    uv_loop_t *uv_main_loop;
    uv_udp_t server_udp;
    uv_async_t *async_works;
    uv_async_t *sending_response_works;

    uv_timer_t current_time_timer;
    uv_timer_t timer;
    uv_timer_t cleanup_timer;


    pthread_spinlock_t queue_lock;
    pthread_spinlock_t forward_table_lock;

    sem_t queue_sem;

    int forward_type;

    pthread_mutex_t sending_lock;

    global_server(const global_server &) = delete;
    void operator=(const global_server &) = delete;

    global_server();

    ~global_server();

    static global_server *server_instance;

    void forward_item_all(objects::forward_item_pointer &);

public:
    void send_response(objects::response *);

    uv_loop_t *get_main_loop()
    {
        return uv_main_loop;
    }

    void forward_item_submit(objects::forward_item *);

    uv_udp_t *get_server_udp()
    {
        return &server_udp;
    }

    void send(objects::send_object *);

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

    const std::vector<remote_nameserver *> &get_remote_server() const
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

    void response_from_remote(uv_buf_t *, remote_nameserver *);

    void cleanup();

    void cache_add_node(record_node *);

    time_t get_time() const
    {
        return current_time;
    }
};


#endif
