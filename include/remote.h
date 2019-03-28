/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// remote.h : DOS upstream

#ifndef RSERVER_H
#define RSERVER_H

#include "athdns.h"
#include "objects.h"
#include "record.h"
#include "utils.h"

#include "fmt/ostream.h"

#include <map>
#include <queue>

namespace remote
{
    class abstract_nameserver
    {
    protected:
        using sending_item_type = std::pair<uint16_t, std::weak_ptr<objects::forward_response>>;

    private:
        sockaddr_in *sock;
        uv_loop_t *loop;
        uv_async_t *stop_async;
        pthread_mutex_t *sending_lock;
        pthread_t *work_thread;

        int remote_port;
        int index;
        ip_address remote_address;

    protected:
        std::map<uint16_t, std::weak_ptr<objects::forward_response>> sending;
        utils::atomic_int request_forward_count;
        utils::atomic_int response_count;

        void set_socket(const ip_address &, uint16_t);

        uv_loop_t *get_loop() const
        {
            return loop;
        }

        void destroy_nameserver();

        // implements of this function should create pthread
        virtual void implement_do_startup() = 0;

        virtual void implement_stop_cb() = 0;

        pthread_t *get_thread() const
        {
            return work_thread;
        }

    public:
        void increase_forward()
        {
            ++request_forward_count;
        }

        bool init_socket();

        void swap(abstract_nameserver &);

        bool find_erase(uint16_t);

        void insert_sending(const sending_item_type &);

        size_t get_sending_size() const
        {
            return sending.size();
        }

        int clean_sent();

        abstract_nameserver(uint32_t, int);
        abstract_nameserver();

        virtual ~abstract_nameserver();

        operator const sockaddr *() const
        {
            return get_sock();
        }

        sockaddr *get_sock() const
        {
            return reinterpret_cast<sockaddr *>(sock);
        }

        int get_index() const
        {
            return index;
        }

        void set_index(int i)
        {
            index = i;
        }

        abstract_nameserver *get_address()
        {
            return this;
        }

        void start_remote();
        void stop_remote();

        virtual void send(objects::send_object *) = 0;
        void init_remote();
        virtual void destroy_remote() = 0;

        const ip_address &get_ip_address() const
        {
            return remote_address;
        }

        void single_thread_check() const
        {
            assert(pthread_self() == *work_thread);
        }

        int get_port() const
        {
            return remote_port;
        }
    };

    struct uv_udp_sending {
        pthread_mutex_t *lock;
        objects::send_object *obj;
        uv_udp_t *handle;
    };

    class udp_nameserver : public remote::abstract_nameserver
    {
        // uv UDP handlers
        uv_udp_t *udp_handler;
        uv_async_t *async_send;
        pthread_mutex_t *sending_queue_mutex;
        std::queue<uv_udp_sending *> sending_queue;

    protected:
        virtual void implement_do_startup() override;

        virtual void implement_stop_cb() override
        {
            uv_udp_recv_stop(udp_handler);
        }

    public:
        udp_nameserver(const ip_address &&, int = 53);
        udp_nameserver(uint32_t, int = 53);
        virtual ~udp_nameserver() override;

        bool operator==(const ip_address &);

        bool operator==(uint32_t ip) const
        {
            return get_ip_address() == ip;
        }

        void swap(const udp_nameserver &);

        virtual void send(objects::send_object *obj) override;
        void init_remote();
        virtual void destroy_remote() override;

        uv_udp_t *get_udp_hander() const
        {
            return udp_handler;
        }

    private:
        udp_nameserver(udp_nameserver &&) = delete;
        udp_nameserver(const udp_nameserver &) = delete;
    };
}  // namespace remote

namespace fmt
{
    template <>
    struct formatter<remote::abstract_nameserver> {
        template <typename PC>
        constexpr auto parse(PC &ctx)
        {
            return ctx.begin();
        }

        template <typename FC>
        auto format(const remote::abstract_nameserver &rname, FC &ctx)
        {
            return format_to(ctx.begin(), "{0}:{1}", rname.get_ip_address(), rname.get_port());
        }
    };
}  // namespace fmt

#endif
