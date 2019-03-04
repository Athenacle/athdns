
#ifndef RSERVER_H
#define RSERVER_H

#include "athdns.h"
#include "objects.h"
#include "record.h"
#include "utils.h"

#include <map>
#include <queue>

namespace remote
{
    class abstract_nameserver
    {
        ip_address remote_address;
        sockaddr_in *sock;

        pthread_mutex_t *sending_lock;
        int remote_port;
        int index;

        using sending_item_type = std::pair<uint16_t, objects::forward_item_pointer>;

    protected:
        std::map<uint16_t, objects::forward_item_pointer> sending;
        utils::atomic_int request_forward_count;
        utils::atomic_int response_count;

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

        virtual void start_remote() = 0;
        virtual void stop_remote() = 0;
        virtual void send(objects::send_object *) = 0;
        virtual void to_string(string &) const = 0;

        const ip_address &get_ip_address() const
        {
            return remote_address;
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

    class remote_nameserver : public remote::abstract_nameserver
    {
        // uv UDP handlers

        uv_loop_t *loop;
        uv_udp_t *udp_handler;

        uv_async_t *async_send;
        uv_async_t *async_stop;

        pthread_mutex_t *lock;
        pthread_t thread;
        std::queue<uv_udp_sending *> sending_queue;

    public:
        remote_nameserver(const ip_address &&, int = 53);
        remote_nameserver(uint32_t, int = 53);
        ~remote_nameserver();

        bool operator==(const ip_address &);

        bool operator==(uint32_t ip) const
        {
            return get_ip_address() == ip;
        }

        void swap(const remote_nameserver &);

        virtual void to_string(string &) const override;

        remote_nameserver *get_address()
        {
            return this;
        }

        virtual void start_remote() override;

        virtual void stop_remote() override;

        virtual void send(objects::send_object *obj) override;

        void init_remote();
        void destroy_remote();

        void start_work();

        uv_loop_t *get_loop() const
        {
            return loop;
        }

        uv_udp_t *get_udp_hander() const
        {
            return udp_handler;
        }

    private:
        remote_nameserver(remote_nameserver &&) = delete;
        remote_nameserver(const remote_nameserver &) = delete;
    };

}  // namespace remote

#endif
