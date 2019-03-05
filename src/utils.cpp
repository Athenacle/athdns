/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// utils.cpp: utilities implements

#include "utils.h"
#include "athdns.h"
#include "logging.h"

#include <unistd.h>

#ifdef HAVE_OPENSSL
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#elif defined HAVE_MBEDTLS
#include <mbedtls/base64.h>
#endif

#include <cctype>
#include <cstdio>
#include <random>
#include <unordered_map>

using namespace utils;
using std::vector;

namespace
{
    int check_all_digit(const string &part)
    {
        return std::stoi(part);
    }

    utils::allocator_pool<char, recv_buffer_size> **get_pool()
    {
        static utils::allocator_pool<char, recv_buffer_size> *pool = nullptr;
        return &pool;
    }

}  // namespace


namespace utils
{
    char *encode_base64(const char *buf)
    {
        return encode_base64(buf, utils::strlen(buf));
    }

    char *encode_base64(const void *buffer, size_t length)
    {
#ifdef HAVE_OPENSSL
        BIO *bio, *b64;
        BUF_MEM *mem_buf;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(bio, buffer, length);
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &mem_buf);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);

        auto len = mem_buf->length;
        auto ret = utils::str_allocate<char>(len + 1);
        memcpy(ret, mem_buf->data, len);
        ret[len] = 0;
        return ret;
#elif defined HAVE_MBEDTLS
        size_t dest_len = 1.5 * length + 5;
        auto ret = utils::str_allocate<unsigned char>(dest_len);
        size_t out_len = 0;

        auto status = mbedtls_base64_encode(
            ret, dest_len, &out_len, reinterpret_cast<const unsigned char *>(buffer), length);
        if (status == 0) {
            return reinterpret_cast<char *>(ret);
        } else {
            return nullptr;
        }
#endif
    }

    char *get_buffer()
    {
        static auto pool = *get_pool();
        return pool->allocate();
    }

    void free_buffer(char *buffer)
    {
        static auto pool = *get_pool();
        pool->deallocate(buffer);
    }

    void destroy_buffer()
    {
        auto pool = *get_pool();
        delete pool;
    }

    void init_buffer_pool(size_t buf_count)
    {
        auto pool = get_pool();
        *pool = new utils::allocator_pool<char, recv_buffer_size>(buf_count);
    }

    uint32_t rand_value()
    {
        static std::random_device rd;
        return rd();
    }

    void split(vector<string> &vec, const CH *s, const CH c)
    {
        const auto bak = strdup(s);
        auto begin = bak;
        auto ptr = bak;
        do {
            for (; *ptr;) {
                if (*ptr == c) {
                    *ptr = 0;
                    vec.emplace_back(begin);
                    begin = ptr = ptr + 1;
                    continue;
                }
                ptr++;
            }
            if (*ptr == 0) {
                if (begin != ptr) {
                    vec.emplace_back(begin);
                }
                break;
            }
        } while (true);
        strfree(bak);
    }

    bool check_ip_address(const CH *ip, uint32_t &address)
    {
        vector<string> ip_part;
        split(ip_part, ip, '.');
        if (ip_part.size() == 4) {
            auto all_digit = true;
            for (auto &part : ip_part) {
                const auto ret = check_all_digit(part);
                all_digit = all_digit && (ret >= 0 && ret <= 255);
                address = (address << 8) | static_cast<uint8_t>(ret);
            }
            return all_digit;
        }
        return false;
    }

    long read_rss()
    {
        static auto page_size = sysconf(_SC_PAGESIZE) / 1024;

        static char buffer[1024];
        long rss = 0xffffffff;
        int fd = open("/proc/self/stat", O_RDONLY);
        if (unlikely(fd == -1)) {
            return 0;
        }
        auto r = read(fd, buffer, 1024);
        close(fd);
        if (likely(r != -1)) {
            char *p = buffer;
            int empty = 0;
            for (; p < buffer + r; p++) {
                if (*p == '(' && *p != 0) {
                    while (*p != ')') {
                        p++;
                    }
                }
                if (*p == 0) {
                    return 0;
                } else if (*p == ' ') {
                    empty++;
                }
                if (empty == 23)
                    break;
            }
            sscanf(++p, "%ld", &rss);
        }
        return rss * page_size;
    }

    bool check_uv_return_status(int status, const char *when)
    {
        if (unlikely(status != 0)) {
            ERROR("{0} failed: {1}", when, uv_strerror(status));
        }
        return status == 0;
    }

}  // namespace utils
