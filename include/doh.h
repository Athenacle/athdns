/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// doh.h : DNS-over-HTTPS header

#ifndef DOH_H
#define DOH_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_DOH_SUPPORT

#include "athdns.h"
#include "record.h"
#include "remote.h"

#ifdef HAVE_OPENSSL
#include <openssl/bio.h>
#include <openssl/ssl.h>
#else
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl.h"
#endif  // HAVE_OPENSSL
#include <nghttp2/nghttp2.h>

using h2f = nghttp2_frame;
using h2s = nghttp2_session;

namespace remote
{
    int h2cb_on_frame_recv(h2s *, const h2f *, void *);

    void *start_thread(void *);

    void uvcb_doh_send(uv_async_t *);
    void uvcb_doh_read(uv_stream_t *, ssize_t, const uv_buf_t *);
    void uvcb_net_rst_recv(uv_async_t *);
    void uvcb_ssl_check(uv_timer_t *);

    enum http_status_code { ok = 200, bad_request = 400, unsupported_media_type = 415 };

    class doh_nameserver : public abstract_nameserver
    {
        friend void uvcb_ssl_check(uv_timer_t *);
        friend void uvcb_net_rst_recv(uv_async_t *);
        friend int h2cb_on_frame_recv(h2s *, const h2f *, void *);
        friend void uvcb_doh_connect(uv_connect_t *, int);
        friend void *start_thread(void *);
        friend void uvcb_doh_send(uv_async_t *);

        enum class ssl_state { not_init, initing, established, closed };
        enum class h2_state { not_init, established, closed };

        struct doh_forward_item {
            int32_t stream_id;
            int32_t status_code;
            double response_time;
            utils::time_object begin_time;
            uv_timer_t *timer;
            doh_nameserver *remote;
            enum class type { h2_frame, dns_request };
            type forward_type;
            union {
                objects::send_object *obj;
                int32_t frame_type;
            } object;

            ~doh_forward_item()
            {
                remote->single_thread_check();
                if (0 != uv_is_active(reinterpret_cast<uv_handle_t *>(timer))) {
                    timer_stop();
                }
                uv_close(reinterpret_cast<uv_handle_t *>(timer), [](uv_handle_t *h) {
                    auto timer = reinterpret_cast<uv_timer_t *>(h);
                    delete timer;
                });
            }

            doh_forward_item() : begin_time()
            {
                timer = new uv_timer_t;
                status_code = -1;
                response_time = 0;
                forward_type = type::dns_request;
            }

            void timer_start(uv_loop_t *loop, doh_nameserver *doh, int timeout = 10)
            {
                doh->single_thread_check();
                remote = doh;
                timer->data = this;
                uv_timer_init(loop, timer);
                uv_timer_start(timer,
                               [](uv_timer_t *timer) {
                                   auto item = reinterpret_cast<doh_forward_item *>(timer->data);
                                   item->remote->forward_item_timeout(item);
                               },
                               timeout * 1000,
                               0);
            }

            void timer_stop()
            {
                uv_timer_stop(timer);
            }
        };

        static std::vector<doh_nameserver *> doh_servers;

        pthread_mutex_t *state_lock;
        uv_tcp_t *tcp_handle;
        uv_timer_t *ssl_state_check;

        pthread_mutex_t *request_queue_mutex;  // protector of queue<send_object*> request_queue

        uv_async_t *async_send;
        sem_t *send_sem;
        uv_async_t *async_rst_handler;
        uv_timer_t *timer_ssl_check;

        int state_check_counter;

        h2s *session;

        const char *url;
        char *path;
        char *domain;
        size_t path_length;
        size_t domain_length;

        ssl_state ssl_status;
        h2_state h2_status;

        utils::atomic_int ssl_version;
        utils::atomic_number<uint8_t> retry;

        std::unordered_map<int64_t, doh_forward_item *> forward_table;
        std::queue<objects::send_object *> request_queue;

        void send(uv_buf_t *);

        void ssl_connect();
        void ssl_renegotiate_worker();
        void ssl_fatal_error(int = 0);

        void h2_terminate();
        void h2_submit(char *);
        void h2_init_session();
        void h2_start();

        void init_uv_handles();

#ifdef HAVE_OPENSSL

        SSL *ssl;
        SSL_CTX *ssl_ctx;
        BIO *read_bio;
        BIO *write_bio;

        bool __openssl_read_check_state(ssize_t, const uv_buf_t *);
        void __openssl_init();
        void __openssl_connect();
        bool __openssl_check_certificate(X509 *, bool = true) const;
        void __openssl_check(int);

        void __openssl_write_bio();
        void __openssl_print_info();
#else
        mbedtls_entropy_context *entropy;
        mbedtls_ssl_context *ssl;
        mbedtls_ssl_config *conf;
        mbedtls_ctr_drbg_context *ctr_drbg;

        int mbedtls_socket_send(int);
        int mbedtls_socket_read(int);
        int mbedtls_ssl_init(int);
        int mbedtls_ssl_destroy();
#endif

        void init_ssl_library(ip_address *);
        void destroy_ssl_library();

        void do_send(objects::send_object *);

        uv_stream_t *get_stream_handle() const
        {
            return reinterpret_cast<uv_stream_t *>(tcp_handle);
        }

        void read(uv_stream_t *, ssize_t, const uv_buf_t *);
        void start();

        virtual void implement_do_startup() override;
        virtual void implement_stop_cb() override;

        void init_path(const char *);

        int current_stream_id;
        int current_stream_sent;

    public:
        enum class error {
            none_error,
            goaway_send,
            goaway_recv,
            h2_timeout,  // h2 error
            fin_recv,
            rst_recv,
            other
        };

    private:
        error current_error;

        void restart_doh();

        void ssl_renegotiate();

        void net_error_handler();

        void forward_item_timeout(doh_forward_item *);

        struct timespec last_sent;

    public:
        doh_nameserver(const char *u);
        virtual ~doh_nameserver();

        void h2_send_special_frame(int32_t, int32_t);
        void h2_recv_special_frame(int32_t, int32_t);

        virtual void send(objects::send_object *) override;
        void send(const uint8_t *, size_t);

        void init_remote();

        virtual void destroy_remote() override;

        static doh_nameserver *dispatch(const SSL *);

        void recv_response_header(int, int);

        void recv_response(int);

        void h2_stream_close(int);

        void h2_submit_data(int, const uint8_t *, size_t);

        void h2_submit_data_finish(int);

        void net_error_handler(error err)
        {
            current_error = err;
            uv_async_send(async_rst_handler);
        }
    };

    inline doh_nameserver *to_doh(void *data)
    {
        return reinterpret_cast<doh_nameserver *>(data);
    }

}  // namespace remote

#endif
#endif
