/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// ssl.cpp: SSL functions for doh_nameserver

#include "doh.h"
#include "logging.h"
#include "server.h"

#ifdef HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

using remote::doh_nameserver;

namespace
{
    // out must at least 60 bytes
    void __format_sha1_buffer(uint8_t* in, char* out)
    {
        int hash_pos = 0;
        for (int pos = 0; pos <= 19; pos++) {
            hash_pos += snprintf(out + hash_pos, 128 - hash_pos, "%02x:", in[pos]);
        }
        out[59] = 0;  // erase trailing :
    }

#ifdef HAVE_OPENSSL

    void __openssl_print_X509_cert(X509* cert)
    {
        if (cert == nullptr) {
            return;
        }

        BIO* tmp = BIO_new(BIO_s_mem());
#if OPENSSL_VERSION_NUMBER < 0x1010000
        auto name = cert->name;
        auto issuser = cert->cert_info->issuer;
#else
        char _name_buffer[128];
        auto sub_name = X509_get_subject_name(cert);
        X509_NAME_oneline(sub_name, _name_buffer, 128);
        const char* name_buffer = _name_buffer;
        auto issuser = X509_get_issuer_name(cert);
#endif
        unsigned char hash_buffer[SHA256_DIGEST_LENGTH];
        unsigned int n;
        auto digest = EVP_get_digestbyname("sha1");
        X509_digest(cert, digest, hash_buffer, &n);

        char issuer_buffer[256];
        X509_NAME_oneline(issuser, issuer_buffer, 256);

        char hash[64];
        __format_sha1_buffer(hash_buffer, hash);

        char not_bufore_buffer[32];
        char not_after_buffer[32];

        auto not_after = X509_get_notAfter(cert);
        auto not_before = X509_get_notBefore(cert);

        ASN1_TIME_print(tmp, not_before);
        BIO_read(tmp, not_bufore_buffer, 32);
        ASN1_TIME_print(tmp, not_after);
        BIO_read(tmp, not_after_buffer, 32);
        not_after_buffer[24] = not_bufore_buffer[24] = 0;

        TRACE("connecting: certificate name {0}", name_buffer);
        TRACE("connecting: issuer {0}", issuer_buffer);
        TRACE("connecting: certificate SHA1 fingerprint {0}", hash);
        TRACE("connecting: certificate not before '{0}', not after '{1}'",
              not_bufore_buffer,
              not_after_buffer);
        BIO_free(tmp);
    }

    int __openssl_cert_cb(SSL* ssl, void*)
    {
        TRACE("{0}", __FUNCTION__);
        const char* cipher_name = SSL_get_cipher_name(ssl);
        const char* version = SSL_get_cipher_version(ssl);
        if (unlikely(cipher_name == nullptr || version == nullptr)) {
            return 0;
        }
        TRACE("connecting: cipher name {0}, via TLS/SSL version: {1}", cipher_name, version);
        X509* cert = SSL_get_peer_certificate(ssl);
        assert(cert != nullptr);
        __openssl_print_X509_cert(cert);
        X509_free(cert);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        const unsigned char* alpn;
        unsigned int size;
        SSL_get0_alpn_selected(ssl, &alpn, &size);
        if (alpn != nullptr) {
            char buffer[64];
            memcpy(buffer, alpn, size);
            buffer[size] = 0;
            TRACE("connecting: ALPN server accepted to use {0}", buffer);
        }
#endif
        return 1;  //refer to SSL_CTX_SET_CERT_CB(3)
    }
#endif  //HAVE_OPENSSL

}  // namespace

#ifdef HAVE_OPENSSL
/* OpenSSL notes:
 *   https://gist.github.com/darrenjs/4645f115d10aa4b5cebf57483ec82eca
 * +------+                                    +-----+
 * |......|--> read(fd) --> BIO_write(rbio) -->|.....|--> SSL_read(ssl)  --> IN
 * |......|                                    |.....|
 * |.sock.|                                    |.SSL.|
 * |......|                                    |.....|
 * |......|<-- write(fd) <-- BIO_read(wbio) <--|.....|<-- SSL_write(ssl) <-- OUT
 * +------+                                    +-----+
 *        |                                    |     |                     |
 *        |<---------------------------------->|     |<------------------->|
 *        |           encrypted bytes          |     |  unencrypted bytes  |
 */
void doh_nameserver::__openssl_print_info()
{
    const char* cipher_name = SSL_get_cipher_name(ssl);
    const char* version = SSL_get_cipher_version(ssl);
    INFO("connected to DoH successfully '{0}'", domain);
    INFO("cipher name {0}, via TLS/SSL version: {1}", cipher_name, version);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    const unsigned char* alpn;
    unsigned int size;
    SSL_get0_alpn_selected(ssl, &alpn, &size);
    if (alpn != nullptr) {
        char buffer[64];
        memcpy(buffer, alpn, size);
        buffer[size] = 0;
        DTRACE("connecting: ALPN, server accepted to use {0}", buffer);
    }
#endif
    X509* cert = SSL_get_peer_certificate(ssl);
    assert(cert != nullptr);
    __openssl_print_X509_cert(cert);
    __openssl_check_certificate(cert);
    X509_free(cert);
    ssl_version.reset(SSL_version(ssl));
}

void doh_nameserver::__openssl_init()
{
    const auto __openssl_info_cb = [](const SSL* ssl, int when, int ret) {
        if (ret == 0) {
            ERROR("SSL error");
        } else if (when & SSL_CB_HANDSHAKE_DONE) {
            auto doh = doh_nameserver::dispatch(ssl);
            doh->single_thread_check();
            if (doh->ssl_status == doh_nameserver::ssl_state::initing) {
                doh->__openssl_print_info();
                doh->h2_init_session();
                doh->h2_start();
                doh->ssl_status = ssl_state::established;
                doh->h2_status = h2_state::established;
                doh->retry.reset(0);
                uv_timer_start(doh->timer_ssl_check, uvcb_ssl_check, 1000, 1000);
            } else {
                WARN("ssl state check failed. This should be an error {0}:{1}", __FILE__, __LINE__);
            }
        }
    };
    single_thread_check();

    if (ssl == nullptr) {
        const auto flag = SSL_OP_ALL | SSL_MODE_NO_AUTO_CHAIN;
        ssl_ctx = SSL_CTX_new(SSLv23_client_method());
        SSL_CTX_set_options(ssl_ctx, flag);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        const uint8_t protos[] = "\02h2\010http/1.1";  // http/1.1 8 bytes, -> \010 OCT
        const auto length = sizeof(protos) - 1;
        // refer to SSL_CTX_SET_ALPN_SELECT_CB(3)
        // protos is a string terminated by NUL, not single array of char.
        SSL_CTX_set_alpn_protos(ssl_ctx, protos, length);
#endif

        ssl = SSL_new(ssl_ctx);
        write_bio = BIO_new(BIO_s_mem());
        read_bio = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl, read_bio, write_bio);
        SSL_set_connect_state(ssl);
        SSL_set_cert_cb(ssl, __openssl_cert_cb, this);
        SSL_set_info_callback(ssl, __openssl_info_cb);
    }
}

void doh_nameserver::__openssl_connect()
{
    ssl_status = ssl_state::initing;
    SSL_clear(ssl);
    SSL_set_connect_state(ssl);
    int ret = SSL_connect(ssl);
    __openssl_write_bio();
    if (ret != 1) {
        __openssl_check(ret);
    }
}

bool doh_nameserver::__openssl_check_certificate(X509* cert, bool) const
{
    auto status = X509_check_host(cert, domain, domain_length, 0, nullptr);
    if (likely(status == 1)) {
        TRACE("connecting: server certificate check success.");
    } else {
        auto name = X509_get_subject_name(cert);
        char name_buffer[128];
        X509_NAME_oneline(name, name_buffer, 128);
        ERROR("connecting: server certificate check failed, name mismatch {0}", name_buffer);
    }
    return true;
}

bool doh_nameserver::__openssl_read_check_state(ssize_t, const uv_buf_t*)
{
    single_thread_check();
    int ret = SSL_connect(ssl);
    __openssl_write_bio();
    if (ret != 1) {
        __openssl_check(ret);
    }
    return false;
}

void doh_nameserver::__openssl_write_bio()
{
    single_thread_check();
    do {
        char* buf = utils::get_buffer();
        int hasread = BIO_read(write_bio, buf, global_buffer_size);
        if (hasread <= 0) {
            utils::free_buffer(buf, global_buffer_size);
            return;
        } else {
            auto uvbuf = global_server::get_server().new_uv_buf_t();
            uvbuf->base = buf;
            uvbuf->len = hasread;
            send(uvbuf);
        }
    } while (true);
}

void doh_nameserver::__openssl_check(int ret)
{
    single_thread_check();
    int error = SSL_get_error(ssl, ret);
    if (error == SSL_ERROR_NONE) {
    } else if (error == SSL_ERROR_WANT_READ) {
    } else if (error == SSL_ERROR_WANT_WRITE) {
        __openssl_write_bio();
    } else {
        ssl_fatal_error(error);
    }
}
#endif  //HAVE_OPENSSL
