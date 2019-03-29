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
#include "remote.h"

#include <pthread.h>
#include <semaphore.h>
#include <sys/prctl.h>

#include <memory>
#include <queue>
#include <unordered_map>

void uvcb_incoming_request_response_send_complete(uv_udp_send_t *, int);

void uvcb_async_response_send(uv_async_t *);

void uvcb_async_remote_response_send(uv_async_t *);

class global_server
{
    friend void uvcb_async_response_send(uv_async_t *);
    friend void uvcb_async_remote_response_send(uv_async_t *async);

    using static_address_type = std::tuple<string, uint32_t>;
    using queue_item = std::tuple<uv_buf_t *, const sockaddr *, ssize_t>;

    using forward_object = std::weak_ptr<objects::forward_response>;

    // listen_address:     ip-string         port     listen_socket uv_udp_handle
    std::vector<std::tuple<const char *, uint16_t, sockaddr *, uv_udp_t *>> listen_address;

    std::vector<remote::abstract_nameserver *> upstream_nameservers;

    std::vector<static_address_type> *static_listen_address;

    std::unordered_map<uint16_t, std::shared_ptr<objects::forward_response>> forward_table;

    std::queue<std::shared_ptr<objects::response>> response_sending_queue;

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
    uv_async_t *async_works;
    uv_async_t *sending_response_works;

    uv_timer_t current_time_timer;
    uv_timer_t reporter_timer;

    pthread_spinlock_t forward_table_lock;

    sem_t queue_sem;

    int forward_type;

#ifdef HAVE_DOH_SUPPORT
    pthread_mutex_t *sync_query_mutex;
    pthread_barrier_t *internal_barrier;
#endif

    global_server(const global_server &) = delete;
    void operator=(const global_server &) = delete;

    global_server();

    ~global_server();

    static global_server *server_instance;

    void forward_item_all(forward_object);

#define ADD_ALLOCATOR_POOL(__type, new_after, delete_before) \
private:                                                     \
    utils::allocator_pool<__type> __type##_pool;             \
                                                             \
public:                                                      \
    template <class... Args>                                 \
    __type *new_##__type(const Args &... __args)             \
    {                                                        \
        auto pointer = __type##_pool.allocate(__args...);    \
        do {                                                 \
            new_after                                        \
        } while (false);                                     \
        return pointer;                                      \
    }                                                        \
    void delete_##__type(__type *p)                          \
    {                                                        \
        do {                                                 \
            delete_before                                    \
        } while (false);                                     \
        __type##_pool.deallocate(p);                         \
    }

    ADD_ALLOCATOR_POOL(uv_buf_t, { pointer->base = nullptr; }, { utils::free_buffer(p->base); })

    ADD_ALLOCATOR_POOL(uv_udp_send_t, {}, {})

#undef ADD_ALLOCATOR_POOL

private:
    void init_server_loop();

    void destroy_ssl_libraries();
    void init_ssl_libraries();

public:
    void send_response(std::shared_ptr<objects::response>);

    uv_loop_t *get_main_loop()
    {
        return uv_main_loop;
    }

    void forward_item_submit(objects::forward_response *);

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

    sem_t *get_semaphore()
    {
        return &queue_sem;
    }

    static void destroy_local_udp_server_instance()
    {
        if (server_instance != nullptr) {
            delete server_instance;
        }
    }

    static void init_local_udp_server_instance()
    {
        server_instance = new global_server;
    }

    static global_server &get_server()
    {
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

    const std::vector<remote::abstract_nameserver *> &get_remote_server() const
    {
        return upstream_nameservers;
    }

    void init_local_udp_server();

    void start_local_udp_server();

    void stop_local_udp_server();

    void response_from_remote(uv_buf_t *, remote::abstract_nameserver *);

    void cache_add_node(record_node *);

    time_t get_current_time() const
    {
        return current_time;
    }

    void config_listen_at(const char *, uint16_t);

#ifdef HAVE_DOH_SUPPORT
    ip_address *sync_internal_query_A(const char *);

    void add_doh_nameserver(const char *);
#endif
};

#endif
