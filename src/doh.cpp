/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// doh.cpp: DNS-over-HTTPS

#include "doh.h"
#include "logging.h"
#include "remote.h"
#include "server.h"

using h2h = nghttp2_headers;
using h2f = nghttp2_frame;
using h2s = nghttp2_session;

using remote::doh_nameserver;
using remote::to_doh;

std::vector<doh_nameserver*> doh_nameserver::doh_servers;

#define TYPE_CASE(value) \
    case value:          \
        ptr = #value;    \
        break;

#define CLEAR_STYLE "\e[0m"
#define BOLD_STYLE "\e[1m"
#define COLOR_STYLE "\e[35m"

namespace
{
    constexpr const char* __dispatch_nghttp2_frame_type(uint8_t type)
    {
        const char* ptr = nullptr;
        switch (type) {
            TYPE_CASE(NGHTTP2_HEADERS)
            case NGHTTP2_GOAWAY:
                ptr = "\e[1m\e[35mNGHTTP2_GOAWAY\e[0m";
                break;
                TYPE_CASE(NGHTTP2_DATA)
                TYPE_CASE(NGHTTP2_PRIORITY)
                TYPE_CASE(NGHTTP2_RST_STREAM)
                TYPE_CASE(NGHTTP2_PUSH_PROMISE)
                TYPE_CASE(NGHTTP2_PING)
                TYPE_CASE(NGHTTP2_WINDOW_UPDATE)
                TYPE_CASE(NGHTTP2_CONTINUATION)
                TYPE_CASE(NGHTTP2_ALTSVC)
                TYPE_CASE(NGHTTP2_ORIGIN)
                TYPE_CASE(NGHTTP2_SETTINGS)
        }
        return ptr;
    }
}  // namespace


namespace
{
    void sigpipe_ingore()
    {
        sigset_t signal_mask;
        sigemptyset(&signal_mask);
        sigaddset(&signal_mask, SIGPIPE);
        int rc = pthread_sigmask(SIG_BLOCK, &signal_mask, nullptr);
        if (rc != 0) {
            ERROR("ignore SIGPIPE error");
        }
    }

    ssize_t h2cb_do_send(h2s*, const uint8_t* data, size_t length, int, void* ptr)
    {
        auto doh = to_doh(ptr);
        doh->send(data, length);
        return (ssize_t)length;
    }

    int h2cb_before_frame_send(h2s*, const h2f* frame, void* user_data)
    {
        const char* ptr = __dispatch_nghttp2_frame_type(frame->hd.type);
        int id = frame->hd.stream_id;
        if (frame->hd.type == NGHTTP2_DATA && frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            DTRACE("entire DATA send for stream {0}", id);
        }
        if (frame->hd.type != NGHTTP2_PING) {
            DTRACE(
                "before frame {2} send. TYPE {0} {1}", ptr, frame->hd.flags == 1 ? "ACK" : "", id);
        }
        if (frame->hd.type == NGHTTP2_GOAWAY) {
            auto doh = to_doh(user_data);
            doh->net_error_handler(doh_nameserver::error::goaway_send);
            DTRACE("{0} send. error {1}", ptr, nghttp2_http2_strerror(frame->goaway.error_code));
        }
        return 0;
    }

    int h2cb_on_stream_close(h2s*, int32_t stream_id, uint32_t error_code, void* user_data)
    {
        DTRACE("nghttp2 stream close, error code {0}, stream id {1}",
               nghttp2_http2_strerror(error_code),
               stream_id);
        to_doh(user_data)->h2_stream_close(stream_id);
        return 0;
    }

    int h2cb_for_header(h2s*,
                        const h2f* frame,
                        const uint8_t* name,
                        size_t name_len,
                        const uint8_t* value,
                        size_t value_len,
                        uint8_t,
                        void* user_data)
    {
        const auto is_status_header = [](const uint8_t* data, uint32_t length) -> auto
        {
            if (length != 7) {
                return false;
            } else {
                return memcmp(":status", data, length) == 0;
            }
        };
        const auto get_status_code = [](const uint8_t* data, uint32_t length) -> int {
            assert(length == 3);
            int ret = data[0] * 100 + data[1] * 10 + data[2] - '0' * 111;
            //ret = (data[0] - '0') * 100 + (data[1] - '0') * 10 + (data[2]) - '0'
            return ret;
        };

        auto doh = to_doh(user_data);
        assert(name_len < recv_buffer_size && value_len < recv_buffer_size);
        auto nb = utils::get_buffer();
        auto vb = utils::get_buffer();
        memcpy(nb, name, name_len);
        memcpy(vb, value, value_len);
        nb[name_len] = 0;
        vb[value_len] = 0;
        auto sh = is_status_header(name, name_len);
        int status = 0;
        if (sh) {
            status = get_status_code(value, value_len);
            DTRACE("status code {0}", status);
            doh->recv_response_header(frame->hd.stream_id, status);
        }
        DTRACE(
            "--> header : {0} = {1} => is status: {2}", nb, vb, is_status_header(name, name_len));
        switch (frame->hd.type) {
            case NGHTTP2_HEADERS:
                if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                    break;
                }
        }
        utils::free_buffer(nb);
        utils::free_buffer(vb);
        return sh ? ((status >= 200 && status < 300) ? 0 : NGHTTP2_ERR_CALLBACK_FAILURE) : 0;
    }

    int h2cb_on_begin_header(h2s*, const h2f* frame, void*)
    {
        switch (frame->hd.type) {
            case NGHTTP2_HEADERS:
                if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                    DTRACE("Response headers for stream ID={0}", frame->hd.stream_id);
                }
                break;
        }
        return 0;
    }

    int h2cb_on_data_chunk_recv(
        h2s*, uint8_t, int32_t sid, const uint8_t* data, size_t len, void* user_data)
    {
#ifdef DTRACE_OUTPUT
        auto b = utils::encode_base64(data, len);
        DTRACE("data chunk recv {0}", b);
        utils::strfree(b);
#endif
        auto doh = to_doh(user_data);
        doh->h2_submit_data(sid, data, len);
        return 0;
    }
}  // namespace

// cbs

namespace remote
{
    int h2cb_on_frame_recv(h2s*, const h2f* frame, void* user_data)
    {
        auto type = frame->hd.type;
        auto doh = to_doh(user_data);
        auto id = frame->hd.stream_id;
        const char* ptr = __dispatch_nghttp2_frame_type(frame->hd.type);
        if (type == NGHTTP2_DATA && frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            DTRACE("entire DATA received. stream_id {0}", frame->hd.stream_id);
            doh->h2_submit_data_finish(id);
            nghttp2_submit_rst_stream(
                doh->session, NGHTTP2_FLAG_NONE, frame->hd.stream_id, NGHTTP2_NO_ERROR);
            nghttp2_session_send(doh->session);
        } else {
            doh->recv_response(id);
        }
        if (type != NGHTTP2_PING && type != NGHTTP2_GOAWAY) {
            DTRACE("{0} type {1}, stream id {2}, length {3}. {4}",
                   __FUNCTION__,
                   ptr,
                   frame->hd.stream_id,
                   frame->data.hd.length,
                   frame->hd.flags == 1 ? "ACK" : " ");
        } else if (type == NGHTTP2_GOAWAY && frame->goaway.error_code != NGHTTP2_NO_ERROR) {
            doh->net_error_handler(doh_nameserver::error::goaway_recv);
            DTRACE("{0} received: {1}", ptr, nghttp2_http2_strerror(frame->goaway.error_code));
        }
        return 0;
    }

    void uvcb_net_rst_recv(uv_async_t* s)
    {
        auto doh = to_doh(s->data);
        doh->net_error_handler();
    }

    void uvcb_ssl_check(uv_timer_t* timer)
    {
        auto doh = to_doh(timer->data);
        if (doh->state_check_counter++ % DOH_KEEP_ALIVE_TIMEOUT == 0) {
            auto status = doh->ssl_status;
            if (status == doh_nameserver::ssl_state::not_init
                || status == doh_nameserver::ssl_state::closed) {
                TRACE("ssl reconnecting...");
                doh->start();
            } else {
                doh->ssl_renegotiate_worker();
            }
        }
        if (doh->h2_status == doh_nameserver::h2_state::established) {
            nghttp2_session_send(doh->session);
        }
    }

    void uvcb_doh_connect(uv_connect_t* conn, int flag)
    {
        const auto read_cb = [](uv_stream_t* s, ssize_t size, const uv_buf_t* buf) {
            auto doh = to_doh(s->data);
            doh->read(s, size, buf);
        };

        auto doh = to_doh(conn->data);
        delete conn;

        if (flag < 0) {
            int timeout = std::pow(2, doh->retry++) * 5;
            ERROR("connecting to {0}:{1} failed: {2}, will retry after {3} seconds",
                  doh->domain,
                  doh->get_port(),
                  uv_strerror(flag),
                  timeout);
            uv_timer_start(doh->timer_ssl_check, uvcb_ssl_check, 1000 * timeout, 0);
            return;
        }
        int ret = uv_read_start(doh->get_stream_handle(), uvcb_server_incoming_alloc, read_cb);
        if (ret == 0) {
            doh->__openssl_init();
            doh->__openssl_connect();
        } else {
            int timeout = std::pow(2, doh->retry++) * 5;
            ERROR("TCP read failed: {0}, retry in {1} seconds", uv_strerror(ret), timeout);
            uv_timer_start(doh->timer_ssl_check, uvcb_ssl_check, timeout * 1000, 0);
        }
    }

    void* start_thread(void* arg)
    {
        auto doh = to_doh(arg);
        char buffer[16] = {0};
        std::snprintf(buffer, 15, "doh-%d", doh->get_index());
        pthread_setname_np(pthread_self(), buffer);

        sigpipe_ingore();
        doh->init_uv_handles();
        uv_timer_init(doh->get_loop(), doh->timer_ssl_check);
        doh->timer_ssl_check->data = doh;
        uv_timer_start(doh->timer_ssl_check, remote::uvcb_ssl_check, 10, 0);
        uv_run(doh->get_loop(), UV_RUN_DEFAULT);
        return nullptr;
    }

}  // namespace remote

// ctor
doh_nameserver::~doh_nameserver()
{
    pthread_mutex_destroy(request_queue_mutex);

    delete async_send;
    delete request_queue_mutex;
    delete tcp_handle;
    delete state_lock;
    delete async_rst_handler;
    delete timer_ssl_check;
    utils::strfree(url);
    utils::strfree(path);
    utils::strfree(domain);
}

void doh_nameserver::init_path(const char* uri)
{
    doh_servers.push_back(this);

    url = utils::strdup(uri);
    string full(uri);
    auto len = utils::strlen(uri);

    path = utils::str_allocate<char>(len);
    domain = utils::str_allocate<char>(len);
    int first_sep = 0;
    for (; uri[first_sep] != 0 && uri[first_sep] != '/'; first_sep++) {
        domain[first_sep] = std::tolower(uri[first_sep]);
    }
    domain[first_sep] = 0;
    domain_length = first_sep;

    if (uri[first_sep] == 0) {
        path[0] = 0;
        path_length = 0;
    } else {
        auto p = path;
        path_length = 0;
        for (; uri[first_sep] != 0; first_sep++) {
            *p = std::tolower(uri[first_sep]);
            path_length++;
            p++;
        }
        *p = 0;
    }
}

doh_nameserver::doh_nameserver(const char* uri)
{
    state_check_counter = 0;

    init_path(uri);
    tcp_handle = new uv_tcp_t;
    tcp_handle->data = this;

    request_queue_mutex = new pthread_mutex_t;
    pthread_mutex_init(request_queue_mutex, nullptr);

    state_lock = new pthread_mutex_t;
    pthread_mutex_init(state_lock, nullptr);

    async_send = new uv_async_t;

    async_rst_handler = new uv_async_t;

    timer_ssl_check = new uv_timer_t;
    timer_ssl_check->data = this;

    h2_status = h2_state::not_init;
    ssl_status = ssl_state::not_init;

    ssl = nullptr;

    current_stream_id = 0;
    current_stream_sent = 0;
}

void doh_nameserver::send(uv_buf_t* buf)
{
    single_thread_check();

    if (uv_is_writable(get_stream_handle())) {
        uv_write_t* wr = new uv_write_t;
        wr->data = buf;
        uv_write(wr, get_stream_handle(), buf, 1, [](uv_write_t* t, int f) {
            if (f < 0) {
                WARN("sending failed: {0}", uv_strerror(f));
            }
            auto buf = reinterpret_cast<uv_buf_t*>(t->data);
            utils::free_buffer(buf->base);
            global_server::get_server().delete_uv_buf_t(buf);
            delete t;
        });
    }
}

void doh_nameserver::implement_do_startup()
{
    pthread_create(get_thread(), nullptr, start_thread, this);
}

void doh_nameserver::start()
{
    single_thread_check();
    ip_address* ip = global_server::get_server().sync_internal_query_A(domain);
    if (unlikely(ip == nullptr)) {
        ERROR("reserve DoH remote '{0}' failed", url);
        return;
    } else {
        set_socket(*ip, 443);
        delete ip;
        uv_connect_t* connect = new uv_connect_t;
        connect->data = this;
        int i = uv_tcp_init(get_loop(), tcp_handle);
        if (i < 0) {
            ERROR("uv_tcp_init status {0}", uv_strerror(i));
        }
        i = uv_tcp_connect(connect, tcp_handle, get_sock(), uvcb_doh_connect);
        if (i < 0) {
            ERROR("uv tcp connect {0}", uv_strerror(i));
        }
    }
}

void doh_nameserver::ssl_renegotiate()
{
    assert(ssl != nullptr);
    single_thread_check();
    if (SSL_is_init_finished(ssl) == 1) {
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
        if (ssl_version == TLS1_3_VERSION) {
            SSL_key_update(ssl, SSL_KEY_UPDATE_REQUESTED);
        } else
#endif
        {
            SSL_renegotiate(ssl);
        }
        SSL_do_handshake(ssl);
        __openssl_write_bio();
    } else {
        __openssl_write_bio();
    }
}

void doh_nameserver::ssl_renegotiate_worker()
{
    static const uint8_t ob[] = "\1\2\3\4\5\6\7\10";  //just for fun
    ssl_renegotiate();
    nghttp2_submit_ping(session, NGHTTP2_FLAG_NONE, ob);
    nghttp2_session_send(session);
}

void send_complete_cb(uv_write_t* req, int flag)
{
    if (unlikely(flag < 0 && flag != UV_EPIPE)) {
        ERROR("send package failed: {0}", uv_strerror(flag));
    }
    auto buf = reinterpret_cast<uv_buf_t*>(req->data);
    if (unlikely(buf->len > recv_buffer_size)) {
        utils::strfree(buf->base);
    } else {
        utils::free_buffer(buf->base);
    }
    global_server::get_server().delete_uv_buf_t(buf);
    delete req;
}

void remote::uvcb_doh_send(uv_async_t* t)
{
    auto doh = to_doh(t->data);
    pthread_mutex_lock(doh->request_queue_mutex);
    while (doh->request_queue.size() > 0) {
        auto obj = doh->request_queue.front();
        doh->request_queue.pop();
        doh->do_send(obj);
    }
    pthread_mutex_unlock(doh->request_queue_mutex);
}

void doh_nameserver::init_uv_handles()
{
    uv_async_init(get_loop(), async_rst_handler, uvcb_net_rst_recv);
    uv_async_init(get_loop(), async_send, uvcb_doh_send);
    async_send->data = async_rst_handler->data = this;
}

void doh_nameserver::h2_init_session()
{
    nghttp2_session_callbacks* callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, h2cb_do_send);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, h2cb_on_frame_recv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, h2cb_on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, h2cb_before_frame_send);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, h2cb_on_stream_close);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, h2cb_for_header);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, h2cb_on_begin_header);
    nghttp2_session_client_new(&session, callbacks, this);
    nghttp2_session_callbacks_del(callbacks);
}

namespace
{
    ssize_t h2cb_data_source_read(h2s*,
                                  int32_t,
                                  uint8_t* buf,
                                  size_t length,
                                  uint32_t* data_flags,
                                  nghttp2_data_source* source,
                                  void* doh)
    {
        to_doh(doh)->single_thread_check();
        auto fd = reinterpret_cast<uv_buf_t*>(source->ptr);
        if (length < fd->len) {
            TRACE("h2cb_data_source_read length too small! length {0}, need {1}", length, fd->len);
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
        memcpy(buf, fd->base, fd->len);
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return fd->len;
    }

    inline void make_header(char* name, size_t nlen, char* value, size_t vlen, nghttp2_nv& head)
    {
        head.name = reinterpret_cast<uint8_t*>(name);
        head.value = reinterpret_cast<uint8_t*>(value);
        head.namelen = nlen;
        head.valuelen = vlen;
        head.flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
    }

#define MAKE_HEADER_ARRAY(NAME, VALUE, HEADER) \
    make_header(NAME, sizeof(NAME) - 1, VALUE, sizeof(VALUE) - 1, HEADER)

#define MAKE_HEADER_ARRAY_2(NAME, VALUE, VALUE_LENGTH, HEADER) \
    make_header(NAME, sizeof(NAME) - 1, VALUE, VALUE_LENGTH, HEADER)

    inline void make_header(
        uv_buf_t* buf, nghttp2_nv h[], char* _path, int plen, char* domain, int dlen)
    {
        static char ua[] = DOH_USER_AGENT;
        static char authority[] = ":authority";
        static char path[] = ":path";
        static char method[] = ":method";
        static char post[] = "POST";
        static char scheme[] = ":scheme";
        static char https[] = "https";

        static char uagent[] = "user-agent";
        static char mime[] = "application/dns-message";
        static char accept[] = "accept";
        static char ctype[] = "content-type";
        static char clength[] = "content-length";

        const size_t cl_buf_len = 8;
        static char cl_buf[cl_buf_len];
        int cl_length = snprintf(cl_buf, cl_buf_len, "%lu", buf->len);

        MAKE_HEADER_ARRAY(method, post, h[0]);
        MAKE_HEADER_ARRAY_2(path, _path, plen, h[1]);
        MAKE_HEADER_ARRAY_2(authority, domain, dlen, h[2]);
        MAKE_HEADER_ARRAY(scheme, https, h[3]);

        MAKE_HEADER_ARRAY(uagent, ua, h[4]);
        MAKE_HEADER_ARRAY(ctype, mime, h[5]);
        MAKE_HEADER_ARRAY(accept, mime, h[6]);

        MAKE_HEADER_ARRAY_2(clength, cl_buf, cl_length, h[7]);
    }
}  // namespace

/* RFC 8484 Section 4.1.1
 * :method = POST
 * :scheme = https
 * :authority = dnsserver.example.net
 * :path = /dns-query
 * accept = application/dns-message
 * content-type = application/dns-message
 * content-length = 33
 *
 * <33 bytes represented by the following hex encoding>
 * 00 00 01 00 00 01 00 00  00 00 00 00 03 77 77 77
 * 07 65 78 61 6d 70 6c 65  03 63 6f 6d 00 00 01 00
 * 01
*/
void doh_nameserver::do_send(objects::send_object* obj)
{
    nghttp2_priority_spec spec;
    nghttp2_priority_spec_init(&spec, 0, 100, 0);

    const int pheaders_length = 8;
    nghttp2_nv pheaders[pheaders_length];

    make_header(obj->bufs, pheaders, this->path, path_length, this->domain, domain_length);

    nghttp2_data_provider ds;
    ds.read_callback = h2cb_data_source_read;
    ds.source.ptr = obj->bufs;

    if (h2_status == h2_state::established) {
        int id;
        id = nghttp2_submit_request(session, &spec, pheaders, pheaders_length, &ds, nullptr);
        DTRACE("output request id {0}", id);
        doh_forward_item* item = new doh_forward_item();
        item->object.obj = obj;
        item->stream_id = id;
        forward_table.insert({id, item});
        nghttp2_session_send(session);
        clock_gettime(ATHDNS_CLOCK_GETTIME_FLAG, &last_sent);
    }
}
#undef MAKE_HEADER_ARRAY

void doh_nameserver::implement_stop_cb()
{
    auto status = h2_status;
    if (status == h2_state::established) {
        nghttp2_submit_shutdown_notice(session);
        nghttp2_session_send(session);
        sleep(1);
        nghttp2_session_del(session);
        uv_read_stop(get_stream_handle());
        destroy_ssl_library();
    }
}

void doh_nameserver::destroy_remote() {}

void doh_nameserver::destroy_ssl_library()
{
    uv_stream_set_blocking(get_stream_handle(), 1);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    ssl = nullptr;
    ssl_ctx = nullptr;
    write_bio = nullptr;
    read_bio = nullptr;
    DTRACE("SSL destroied");
}

void doh_nameserver::send(const uint8_t* buf, size_t s)
{
    single_thread_check();
    if (s == 0) {
        return;
    }
    int ret = SSL_write(ssl, buf, s);
    if (ret <= 0) {
        __openssl_check(ret);
    } else {
        char* buffer = utils::get_buffer();
        int read_size = BIO_read(write_bio, buffer, recv_buffer_size);
        if (read_size <= 0) {
            __openssl_check(read_size);
        } else {
            auto uvbuffer = global_server::get_server().new_uv_buf_t();
            uvbuffer->base = buffer;
            uvbuffer->len = read_size;
            send(uvbuffer);
        }
    }
    do {
        const size_t buffer_size = recv_buffer_size;
        uint8_t buffer[buffer_size];
        ret = SSL_read(ssl, buffer, recv_buffer_size);
        if (ret > 0) {
            nghttp2_session_mem_recv(session, buffer, ret);
            nghttp2_session_send(session);
            if (ret == buffer_size) {
                continue;
            }
        }
    } while (false);
}

void doh_nameserver::read(uv_stream_t*, ssize_t size, const uv_buf_t* buf)
{
    single_thread_check();

    if (size == UV_EOF) {
        net_error_handler(error::fin_recv);
        return;
    } else if (size == UV_ECONNRESET) {
        net_error_handler(error::rst_recv);
    } else if (size <= 0) {
        ERROR("read recv error {0}", uv_strerror(size));
        return;
    }
    uint8_t buffer[1024];
    BIO_write(read_bio, buf->base, size);
    int finished = SSL_is_init_finished(ssl);
    if (finished == 0) {
        __openssl_read_check_state(size, buf);
    } else {
        int ret = SSL_read(ssl, buffer, sizeof(buffer));
        if (ret < 0) {
            __openssl_check(ret);
        } else {
            nghttp2_session_mem_recv(session, buffer, ret);
            nghttp2_session_send(session);
        }
    }
    utils::free_buffer(buf->base);
}

void doh_nameserver::h2_terminate()
{
    single_thread_check();
    auto state = h2_status;
    if (state == h2_state::established) {
        destroy_ssl_library();
        nghttp2_session_del(session);
    }
}

void doh_nameserver::ssl_fatal_error(int ec)
{
    if (ec == SSL_ERROR_NONE) {
        return;
    }
    auto buf = utils::get_buffer();
    ERROR("ssl fatal error. {0}", buf);
    utils::free_buffer(buf);
}

void doh_nameserver::h2_start()
{
    constexpr nghttp2_settings_entry iv[3] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 256},
        {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 6},
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
    };
    nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 3);
    nghttp2_session_send(session);
}

doh_nameserver* doh_nameserver::dispatch(const SSL* ssl)
{
    auto itor = std::find_if(
        doh_servers.cbegin(), doh_servers.cend(), [=](auto& doh) { return doh->ssl == ssl; });
    if (unlikely(itor == doh_servers.cend())) {
        FATAL("doh nameserver dispatch failed...");
    }
    return *itor;
}

void doh_nameserver::net_error_handler()
{
    if (current_error == error::none_error) {
        return;
    } else if (current_error == error::goaway_send || current_error == error::goaway_recv) {
        ssl_status = ssl_state::closed;
        h2_status = h2_state::closed;
    } else if (current_error == error::rst_recv || current_error == error::fin_recv) {
        TRACE("TCP RST/FIN received, restart ");
    }
    restart_doh();
}

void doh_nameserver::restart_doh()
{
    uv_read_stop(get_stream_handle());
    uv_timer_stop(timer_ssl_check);

    ssl_status = ssl_state::closed;
    h2_status = h2_state::closed;

    if (ssl != nullptr) {
        BIO_reset(read_bio);
        BIO_reset(write_bio);
        SSL_clear(ssl);
    }
    if (session != nullptr) {
        nghttp2_session_del(session);
        session = nullptr;
    }

    uv_shutdown_t* down = new uv_shutdown_t;
    down->data = this;

    int de = uv_shutdown(down, get_stream_handle(), [](uv_shutdown_t* st, int i) {
        if (i < 0 && i != UV_ENOTCONN) {
            WARN("shutdown failed: {0}", uv_strerror(i));
        }
        auto doh = to_doh(st->data);
        uv_timer_start(doh->timer_ssl_check, uvcb_ssl_check, 1500, 0);
        delete st;
    });

    if (de < 0) {
        WARN("shutdown {0} close {1}", uv_strerror(de), 0);
        uv_timer_start(timer_ssl_check, uvcb_ssl_check, 1500, 0);
    }
}

void doh_nameserver::send(objects::send_object* obj)
{
    pthread_mutex_lock(request_queue_mutex);
    request_queue.emplace(obj);
    pthread_mutex_unlock(request_queue_mutex);
    uv_async_send(async_send);
}

void doh_nameserver::recv_response_header(int sid, int sc)
{
    auto itor = forward_table.find(sid);
    if (itor == forward_table.end()) {
        return;
    } else {
        itor->second->status_code = sc;
        if (sc != 200) {
            if (sc > 500) {
                WARN("receive http status code {0} return from stream id {1}", sc, sid);
            } else if (sc > 400) {
                if (sc == 404) {
                    WARN(
                        "receive http status code 404, Not Found, please check your DNS-over-Https "
                        "server settings.");
                } else {
                    ERROR("receive http status code {0}, this should be internal error", sc);
                    net_error_handler(error::other);
                }
            }
        }
    }
}

void doh_nameserver::recv_response(int sid)
{
    auto itor = forward_table.find(sid);
    if (itor == forward_table.end()) {
        return;
    } else {
        auto p = itor->second;
        if (p->response_time == 0) {
            utils::time_object current;
            p->response_time = utils::time_object::diff_to_ms(current, itor->second->begin_time);
        }
    }
}

void doh_nameserver::h2_stream_close(int stream_id)
{
    auto itor = forward_table.find(stream_id);
    if (itor == forward_table.end()) {
        return;
    } else {
        DTRACE("h2 request for stream {0} closed, cost time {1:2.2f} ms",
               stream_id,
               itor->second->response_time);
        delete itor->second;
        forward_table.erase(itor);
    }
}

void doh_nameserver::h2_submit_data_finish(int) {}

void doh_nameserver::h2_submit_data(int stream_id, const uint8_t* data, size_t len)
{
    auto itor = forward_table.find(stream_id);
    if (itor == forward_table.end()) {
        return;
    } else {
        if (itor->second->status_code == 200) {
            char* buf;
            if (len > recv_buffer_size) {
                buf = utils::str_allocate<char>(len);
            } else {
                buf = utils::get_buffer();
            }
            memcpy(buf, data, len);
            auto uvbuf = global_server::get_server().new_uv_buf_t();
            uvbuf->base = buf;
            uvbuf->len = len;
            global_server::get_server().response_from_remote(uvbuf, this);
        }
    }
}
