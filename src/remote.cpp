/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// remote.cpp: remote server implements

#include "remote.h"
#include "logging.h"
#include "server.h"

#ifdef HAVE_MBEDTLS
#include <mbedtls/error.h>
#include <mbedtls/sha1.h>
#endif

using namespace remote;

abstract_nameserver::~abstract_nameserver()
{
    pthread_mutex_destroy(sending_lock);
    delete sending_lock;
    delete sock;
    delete loop;
    delete stop_async;
}

abstract_nameserver::abstract_nameserver(uint32_t __remote_ip, int __remote_port)
    : abstract_nameserver()
{
    remote_address.reset(__remote_ip);
    remote_port = __remote_port;
    init_socket();
}

abstract_nameserver::abstract_nameserver()
{
    sending_lock = new pthread_mutex_t;
    pthread_mutex_init(sending_lock, nullptr);
    index = 0;
    sock = nullptr;
    loop = new uv_loop_t;
    loop->data = this;
    stop_async = new uv_async_t;
    stop_async->data = this;
    work_thread = new pthread_t;
}

void abstract_nameserver::swap(abstract_nameserver& an)
{
    std::swap(remote_port, an.remote_port);
    std::swap(remote_address, an.remote_address);
    std::swap(sending, an.sending);
    std::swap(request_forward_count, an.request_forward_count);
    std::swap(response_count, an.response_count);
    sock = an.sock;
    an.sock = nullptr;
    index = an.index;
}

bool abstract_nameserver::init_socket()
{
    sock = new sockaddr_in;
    string ip_string;
    remote_address.to_string(ip_string);
    auto ret = uv_ip4_addr(ip_string.c_str(), remote_port, sock);
    return ret == 0;
}

int abstract_nameserver::clean_sent()
{
    int count = 0;
    pthread_mutex_lock(sending_lock);
    const auto& end = sending.end();
    for (auto itor = sending.begin(); itor != end;) {
        if (itor->second->get_response_send()) {
            itor = sending.erase(itor);
            count++;
        } else {
            ++itor;
        }
    }
    pthread_mutex_unlock(sending_lock);
    return count;
}

void abstract_nameserver::insert_sending(const sending_item_type& pair)
{
    pthread_mutex_lock(sending_lock);
    sending.insert(pair);
    pthread_mutex_unlock(sending_lock);
}

bool abstract_nameserver::find_erase(uint16_t id)
{
    pthread_mutex_lock(sending_lock);
    auto itor = sending.find(id);
    auto found = itor != sending.end();
    if (found) {
        sending.erase(itor);
    }
    pthread_mutex_unlock(sending_lock);
    return found;
}

void abstract_nameserver::destroy_nameserver()
{
    uv_loop_close(loop);
}

void abstract_nameserver::set_socket(const ip_address& ip, uint16_t port)
{
    remote_address = ip;
    remote_port = port;
    init_socket();
}

void abstract_nameserver::start_remote()
{
    const auto async_cb = [](uv_async_t* async) {
        abstract_nameserver* an = reinterpret_cast<abstract_nameserver*>(async->data);
        static const auto& walk = [](uv_handle_t* t, void*) { uv_close(t, nullptr); };
        an->implement_stop_cb();
        uv_walk(an->get_loop(), walk, nullptr);
        uv_stop(an->get_loop());
        uv_loop_close(an->get_loop());
    };
    uv_loop_init(loop);
    uv_async_init(loop, stop_async, async_cb);
    implement_do_startup();
}

void abstract_nameserver::stop_remote()
{
    uv_async_send(stop_async);
    pthread_join(*work_thread, nullptr);
}

// remote_nameserver

udp_nameserver::~udp_nameserver()
{
    delete udp_handler;
    delete async_send;
    delete sending_queue_mutex;
}

udp_nameserver::udp_nameserver(const ip_address&& addr, int port)
    : udp_nameserver(addr.get_address(), port)
{
}

udp_nameserver::udp_nameserver(uint32_t addr, int p) : remote::abstract_nameserver(addr, p)
{
    async_send = new uv_async_t;
    udp_handler = new uv_udp_t;
    sending_queue_mutex = new pthread_mutex_t;

    async_send->data = udp_handler->data = this;
    pthread_mutex_init(sending_queue_mutex, nullptr);
}

void udp_nameserver::init_remote()
{
    static const auto& complete = [](uv_udp_send_t* send, int flag) {
        if (unlikely(flag < 0)) {
            WARN("send error {0}", uv_err_name(flag));
        }

        auto sending = reinterpret_cast<uv_udp_sending*>(send->data);
        delete sending->obj;
        delete sending;
        global_server::get_server().delete_uv_udp_send_t(send);
    };

    const auto& send_cb = [](uv_async_t* send) {
        auto sending_obj = reinterpret_cast<udp_nameserver*>(send->data);

        pthread_mutex_lock(sending_obj->sending_queue_mutex);
        while (sending_obj->sending_queue.size() > 0) {
            auto i = sending_obj->sending_queue.front();
            sending_obj->sending_queue.pop();
            uv_udp_send_t* sending = global_server::get_server().new_uv_udp_send_t();
            sending->data = i;
            auto flag = uv_udp_send(
                sending, i->handle, i->obj->bufs, i->obj->bufs_count, i->obj->sock, complete);
            if (unlikely(flag < 0)) {
                ERROR("send failed: {0}", uv_err_name(flag));
            }
        }
        pthread_mutex_unlock(sending_obj->sending_queue_mutex);
    };

    auto l = get_loop();
    uv_async_init(l, async_send, send_cb);
    uv_udp_init(l, udp_handler);
}

void udp_nameserver::send(objects::send_object* obj)
{
    uv_udp_sending* sending = new uv_udp_sending;
    sending->lock = sending_queue_mutex;
    sending->handle = udp_handler;
    sending->obj = obj;

    pthread_mutex_lock(sending_queue_mutex);
    sending_queue.emplace(sending);
    pthread_mutex_unlock(sending_queue_mutex);
    uv_async_send(async_send);
}

void udp_nameserver::destroy_remote()
{
    pthread_mutex_destroy(sending_queue_mutex);
    destroy_nameserver();
}

void udp_nameserver::implement_do_startup()
{
    static const auto& thread_func = [](void* param) -> void* {
        auto pointer = reinterpret_cast<udp_nameserver*>(param);
        auto loop = pointer->get_loop();
        auto udp = pointer->get_udp_hander();
        uv_udp_recv_start(udp, uvcb_server_incoming_alloc, uvcb_remote_udp_recv);
        uv_run(loop, UV_RUN_DEFAULT);
        return nullptr;
    };

    init_remote();
    pthread_create(get_thread(), nullptr, thread_func, this);
}

#ifdef HAVE_DOH_SUPPORT

doh_nameserver::doh_nameserver(const char* u) : domain(u)
{
    url = utils::strdup(u);
    handle = new uv_tcp_t;
    domain = domain.substr(0, domain.find_first_of('/'));
    state_lock = new pthread_spinlock_t;
    pthread_spin_init(state_lock, PTHREAD_PROCESS_PRIVATE);
    state = ssl_state::not_init;
}

doh_nameserver::~doh_nameserver()
{
    utils::strfree(url);
    pthread_spin_destroy(state_lock);
    delete state_lock;
}

void doh_nameserver::implement_do_startup()
{
    static const auto& worker = [this]() { this->start(); };

    static const auto& thread = [](void*) -> void* {
        worker();
        return nullptr;
    };

    pthread_create(get_thread(), nullptr, thread, nullptr);
}

void doh_nameserver::implement_stop_cb()
{
    //TODO: implement this
    DTRACE("{0}", __FUNCTION__);

    destroy_ssl_library();
}

void doh_nameserver::send(objects::send_object*)
{
    //TODO: implement this
}

void doh_nameserver::init_remote()
{
    //init remote, we are now on work thread
    ip_address* remote = global_server::get_server().sync_internal_query_A(domain.c_str());
    if (remote == nullptr) {
        ERROR("reslove DoH domain {0} failed", domain);
        return;
    } else {
        init_ssl_library(remote);
    }
}

void doh_nameserver::destroy_ssl_library()
{
    uv_read_stop(get_stream_handle());

    int ctl = fcntl(sock_fd, F_SETFD, O_RSYNC);
    if (ctl == -1) {
        ERROR("fcntl error {0}", strerror(errno));
    }
#ifdef HAVE_OPENSSL
    openssl_ssl_destroy();
#else
    mbedtls_ssl_destroy();
#endif
    shutdown(sock_fd, SHUT_RDWR);
    ::close(sock_fd);
    sock_fd = 0;
}

void doh_nameserver::init_ssl_library(ip_address* remote)
{
    set_socket(*remote, 443);
    sockaddr_in* sock = reinterpret_cast<sockaddr_in*>(get_sock());

    uv_os_sock_t fd;
    fd = socket_connect(sock);
    if (fd != -1) {
        set_state(ssl_state::initing);
#ifdef HAVE_OPENSSL
        fd = openssl_ssl_init(fd);
#else
        fd = mbedtls_ssl_init(fd);
#endif
        sock_fd = fd;
        uv_tcp_init(get_loop(), handle);
        uv_tcp_open(handle, fd);
        uv_run(get_loop(), UV_RUN_DEFAULT);
    } else {
    }
}

void doh_nameserver::destroy_remote()
{
    //TODO: implement this
}

void doh_nameserver::start()
{
    // now we are on other thread instead of main thread, so we can call sync calls.
    init_remote();
}

int doh_nameserver::socket_connect(const sockaddr_in* sock)
{
    int fd = -1;
    for (int i = 0; i < 3; i++) {
        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (fd == -1) {
            ERROR("create socket failed: {0}", strerror(errno));
        } else {
            int status = connect(fd, reinterpret_cast<const sockaddr*>(sock), sizeof(*sock));
            if (status == -1) {
                auto s = std::pow(2, i);
                DTRACE("connect failed: {0}, sleep {1}", strerror(errno), s);
                sleep(s);
            } else {
                DTRACE("connect success. fd: {0}", fd);
                return fd;
            }
        }
        close(fd);
    }
    return -1;
}

namespace
{
    void format_sha1_buffer(unsigned char* in, char* out)
    {
        int hash_pos = 0;
        for (int pos = 0; pos <= 19; pos++) {
            hash_pos += snprintf(out + hash_pos, 128 - hash_pos, "%02x:", in[pos]);
        }
        out[59] = 0;
    }

};  // namespace

#ifdef HAVE_OPENSSL
namespace
{
    void __openssl_print_X509_cert(X509* cert)
    {
        if (cert == nullptr) {
            return;
        }

        BIO* tmp = BIO_new(BIO_s_mem());
        auto name = cert->name;
        auto issuser = cert->cert_info->issuer;

        unsigned char hash_buf[SHA512_DIGEST_LENGTH];
        unsigned int n;
        auto digest = EVP_get_digestbyname("sha1");
        X509_digest(cert, digest, hash_buf, &n);

        char buffer[256];
        X509_NAME_oneline(issuser, buffer, 256);

        char hash[64];
        format_sha1_buffer(hash_buf, hash);

        char nb[64];
        char na[64];

        auto not_after = X509_get_notAfter(cert);
        auto not_before = X509_get_notBefore(cert);

        ASN1_TIME_print(tmp, not_before);
        BIO_read(tmp, nb, 64);
        ASN1_TIME_print(tmp, not_after);
        BIO_read(tmp, na, 64);

        INFO("certificate name {0}, issuer {1}", name, buffer);
        INFO("certificate SHA1 fingerprint {0}", hash);
        INFO("certificate not before '{0}', not after '{1}'", nb, na);

        BIO_free(tmp);
    }
}  // namespace

int doh_nameserver::openssl_ssl_destroy()
{
    DTRACE("{0}", __FUNCTION__);

    int ret;
    while ((ret = SSL_shutdown(ssl)) == 0) {
        openssl_socket_send(sock_fd);
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ) {
            openssl_socket_read(sock_fd);
        } else if (err == SSL_ERROR_WANT_WRITE) {
            openssl_socket_send(sock_fd);
        }
    }

    SSL_free(ssl);
    BIO_free(write_bio);
    BIO_free(read_bio);
    SSL_CTX_free(ssl_ctx);
    ssl = nullptr;
    ssl_ctx = nullptr;
    write_bio = nullptr;
    read_bio = nullptr;
    return 0;
}

int doh_nameserver::openssl_ssl_init(int fd)
{
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    ssl = SSL_new(ssl_ctx);
    write_bio = BIO_new(BIO_s_mem());
    read_bio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, read_bio, write_bio);
    if (fd != -1) {
        SSL_set_connect_state(ssl);
        do {
            int ret = SSL_connect(ssl);
            openssl_socket_send(fd);
            if (ret != 1) {
                int err = SSL_get_error(ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    openssl_socket_read(fd);
                } else if (err == SSL_ERROR_WANT_WRITE) {
                    openssl_socket_send(fd);
                }
            }
        } while (SSL_is_init_finished(ssl) == 0);
        assert(SSL_is_init_finished(ssl) == 1);
        const char* cipher_name = SSL_get_cipher_name(ssl);
        const char* version = SSL_get_cipher_version(ssl);
        INFO("connected to DoH successfully '{0}'", domain);
        INFO("cipher name {0}, via TLS/SSL version: {1}", cipher_name, version);
        X509* cert = SSL_get_peer_certificate(ssl);
        assert(cert != nullptr);
        __openssl_print_X509_cert(cert);
        X509_free(cert);
    }
    return fd;
}

int doh_nameserver::openssl_socket_read(int fd)
{
    const size_t buf_size = 1024;
    char buf[buf_size];
    int read_size = 0;
    do {
        int size = ::recv(fd, buf, buf_size, 0);
        if (size == -1) {
            ERROR("recv error: {0}", strerror(errno));
        }

        if (size > 0) {
            int rs = BIO_write(read_bio, buf, size);
            read_size += rs;
        }
        if (size == buf_size) {
            continue;
        }
    } while (false);
    return read_size;
}

int doh_nameserver::openssl_socket_send(int sock)
{
    const size_t buf_size = 1024;
    char buf[buf_size];
    int sent = 0;
    do {
        int size = BIO_read(write_bio, buf, sizeof(buf));
        if (size <= 0) {
            return sent;
        }
        int status = ::send(sock, buf, size, 0);
        if (status == -1) {
            assert(0);
        } else {
            sent += size;
        }
        if (size == buf_size) {
            continue;
        }
    } while (false);
    return sent;
}

#else
namespace
{
    int __mbedtls_send(void* ctx, const unsigned char* buf, size_t len)
    {
        int fd = *reinterpret_cast<int*>(ctx);
        return ::send(fd, buf, len, 0);
    }

    int __mbedtls_recv(void* ctx, unsigned char* buf, size_t len)
    {
        int fd = *reinterpret_cast<int*>(ctx);
        return ::recv(fd, buf, len, 0);
    }

    int __mbedtls_load_ca(mbedtls_x509_crt* ca)
    {
        const char root[] = "/etc/ssl/certs/ca-certificates.crt";
        if (access("/etc/ssl/certs/ca-certificates.crt", R_OK) == 0) {
            if (0 != mbedtls_x509_crt_parse_file(ca, root)) {
                return -1;
            }
        }
        return 0;
    }

    int __mbedtls_print_x509(const mbedtls_x509_crt* crt)
    {
        unsigned char sha1_buf[64];
        char hash[64];
        mbedtls_sha1(crt->raw.p, crt->raw.len, sha1_buf);
        format_sha1_buffer(sha1_buf, hash);
        INFO("remote certificate SHA1 fingerprint {0}", hash);
        return 0;
    }
}  // namespace

int doh_nameserver::mbedtls_ssl_destroy()
{
    mbedtls_ssl_close_notify(ssl);
    return 0;
}

int doh_nameserver::mbedtls_ssl_init(int fd)
{
    ssl = new mbedtls_ssl_context;
    conf = new mbedtls_ssl_config;
    entropy = new mbedtls_entropy_context;
    ctr_drbg = new mbedtls_ctr_drbg_context;

    mbedtls_x509_crt* root_ca = new mbedtls_x509_crt;
    mbedtls_x509_crt_init(root_ca);
    __mbedtls_load_ca(root_ca);

    ::mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, 0, 0);
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);

    auto ret = ::mbedtls_ssl_config_defaults(
        conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(conf, root_ca, nullptr);
    mbedtls_ssl_setup(ssl, conf);
    mbedtls_ssl_set_bio(ssl, &fd, __mbedtls_send, __mbedtls_recv, nullptr);
    do {
        ret = mbedtls_ssl_handshake(ssl);
        if (ret == 0) {
            WARN("mbedtls connected successfully.");
            break;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            continue;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        } else {
            char buffer[128];
            mbedtls_strerror(ret, buffer, 128);
            WARN("mbedtls connected partical {0:x} {1}", ret, buffer);
            break;
        }
    } while (true);
    if (ret == 0) {
        auto verify = mbedtls_ssl_get_verify_result(ssl);
        if (verify == 0) {
            INFO("connected to DoH successfully '{0}'", domain);
            INFO("cipher {0}, TLS version {1}",
                 mbedtls_ssl_get_ciphersuite(ssl),
                 mbedtls_ssl_get_version(ssl));
            auto cert = mbedtls_ssl_get_peer_cert(ssl);
            if (cert != nullptr) {
                __mbedtls_print_x509(cert);
            }
        }
    }

    mbedtls_x509_crt_free(root_ca);
    delete root_ca;

    return fd;
}
#endif
#endif
