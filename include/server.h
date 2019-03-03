
#pragma once

#ifndef SERVER_H
#define SERVER_H


#include "dns.h"
#include "dnsserver.h"
#include "hash.h"

#include <pthread.h>
#include <semaphore.h>
#include <sys/prctl.h>

#include <map>
#include <memory>
#include <queue>
#include <unordered_map>

void uvcb_incoming_request_worker(uv_work_t *);

void uvcb_incoming_request_response_send_complete(uv_udp_send_t *, int);

void uvcb_remote_recv(uv_udp_t *, ssize_t, const uv_buf_t *, const sockaddr *, unsigned int);

void uvcb_async_response_send(uv_async_t *);

void uvcb_async_remote_response_send(uv_async_t *);

void uvcb_remote_nameserver_send_complete(uv_udp_send_t *, int);

void uvcb_async_remote_send(uv_async_t *);

void uvcb_timer_cleaner(uv_timer_t *);

struct send_object {
    const sockaddr *sock;
    uv_buf_t *bufs;
    int bufs_count;
};

struct uv_udp_sending {
    pthread_mutex_t *lock;
    send_object *obj;
    uv_udp_t *handle;
};

struct uv_udp_nameserver_runnable {
    uv_loop_t *loop;
    uv_udp_t *udp;
    uv_async_t *async;
    uv_async_t *async_send;
    pthread_mutex_t *lock;
    pthread_t thread;
    static utils::atomic_int count;

    std::queue<uv_udp_sending *> sending_queue;

public:
    uv_udp_nameserver_runnable() {}

    void set_data(void *p)
    {
        udp->data = p;
    }

    void swap(uv_udp_nameserver_runnable &ns);

    void init();

    void start(uv_run_mode mode = UV_RUN_DEFAULT);

    void stop();
    void send(send_object *);
    void destroy();
};

struct request {
    uv_buf_t *buf;
    ssize_t nsize;
    const sockaddr *sock;
    dns::DnsPacket *pack;

    request(const uv_buf_t *, ssize_t, const sockaddr *);
    ~request();
};

using request_pointer = std::shared_ptr<request>;

class response
{
    request_pointer req;

protected:
    uv_buf_t *response_buffer;

public:
    response(const request_pointer &);

    virtual ~response();

    const request_pointer &get_request() const
    {
        return req;
    }

    uv_buf_t *get_buffer() const
    {
        return response_buffer;
    }

    const sockaddr *get_sock() const
    {
        return req->sock;
    }
};

class found_response : public response
{
    dns::DnsPacket *packet;

public:
    found_response(dns::DnsPacket *, const request_pointer &);

    virtual ~found_response();
};

struct forward_item {
    request_pointer req;

    dns::DnsPacket *pack;

    uint16_t forward_id;
    uint16_t origin_id;
    pthread_spinlock_t _lock;

    bool response_send;

    void lock()
    {
        pthread_spin_lock(&_lock);
    }

    void unlock()
    {
        pthread_spin_unlock(&_lock);
    }


    void set_response_send()
    {
        pthread_spin_lock(&_lock);
        response_send = true;
        pthread_spin_unlock(&_lock);
    }

    bool get_response_send()
    {
        pthread_spin_lock(&_lock);
        auto rs = response_send;
        pthread_spin_unlock(&_lock);
        return rs;
    }

    forward_item(dns::DnsPacket *, const request_pointer &);

    ~forward_item();
};

using forward_item_pointer = std::shared_ptr<forward_item>;

struct forward_response : public response {
    forward_item_pointer pointer;

    forward_response(forward_item_pointer &item, uv_buf_t *b) : response(item->req), pointer(item)
    {
        uint16_t *p = reinterpret_cast<uint16_t *>(b->base);
        *p = item->origin_id;
        response_buffer = b;
    }

    virtual ~forward_response();
};

struct remote_nameserver {
    uv_udp_nameserver_runnable run;

    int index;
    int port;
    sockaddr_in *sock;
    ip_address ip;

    pthread_spinlock_t *sending_lock;
    std::map<uint16_t, forward_item_pointer> sending;

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


    void to_string(string &) const;

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

    void start_remote();

    void stop_remote()
    {
        run.stop();
        pthread_join(run.thread, nullptr);
    }

    void send(send_object *obj);


private:
    remote_nameserver(const remote_nameserver &) = delete;
};

struct forward_queue_item {
    forward_item_pointer item;
    int ns_index;
};

class global_server
{
    friend void delete_timer_worker(uv_timer_t *);
    friend void uvcb_async_stop_loop(uv_async_t *);
    friend void uvcb_async_response_send(uv_async_t *);
    friend void uvcb_timer_cleaner(uv_timer_t *);
    friend void uvcb_async_remote_response_send(uv_async_t *async);

    using static_address_type = std::tuple<string, uint32_t>;
    using queue_item = std::tuple<uv_buf_t *, const sockaddr *, ssize_t>;

    std::vector<remote_nameserver> remote_address;
    std::vector<static_address_type> *static_address;

    std::unordered_map<uint16_t, forward_item_pointer> forward_table;

    std::queue<response *> response_sending_queue;

    pthread_mutex_t *response_sending_queue_lock;

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
    uv_udp_t server_udp;
    uv_async_t *async_works;
    uv_async_t *sending_response_works;

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

    void forward_item_all(forward_item_pointer &);

public:
    void send_response(response *);

    uv_loop_t *get_main_loop()
    {
        return uv_main_loop;
    }

    void forward_item_submit(forward_item *);

    uv_udp_t *get_server_udp()
    {
        return &server_udp;
    }

    void send(send_object *);

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

    const std::vector<remote_nameserver> &get_remote_server() const
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
};


#endif
