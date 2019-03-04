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

    inline std::queue<char *> &get_empty_pool()
    {
        static std::queue<char *> empty_pool;
        return empty_pool;
    }

    inline std::vector<char *> &get_pool()
    {
        static std::vector<char *> pool;
        return pool;
    }

    inline pthread_mutex_t *get_mutex()
    {
        static pthread_mutex_t mutex;
        return &mutex;
    }

    const bool buffer_used = true;

    struct map_entry {
        size_t offset;
        bool used;
        map_entry(size_t t) : offset(t)
        {
            used = !buffer_used;
        }
    };

    inline std::unordered_map<char *, map_entry *> &get_pointer_map()
    {
        static std::unordered_map<char *, map_entry *> map;
        return map;
    }

    void resize_pool(size_t new_size)
    {
        auto &eq = get_empty_pool();
        auto &vec = get_pool();
        auto &map = get_pointer_map();
        vec.reserve(new_size);
        map.reserve(new_size);
        for (size_t i = vec.size(); i < new_size; i++) {
            auto p = new char[recv_buffer_size];
            vec.emplace_back(p);
            eq.emplace(p);
            map.insert({p, new map_entry(i)});
        }
    }
}  // namespace


namespace utils
{
    char *get_buffer()
    {
        auto mutex = get_mutex();
        auto &map = get_pointer_map();
        auto &eq = get_empty_pool();
        char *ret = nullptr;
        pthread_mutex_lock(mutex);
        {
            if (unlikely(eq.empty())) {
                resize_pool(map.size() << 1);
            }
            ret = eq.front();
            eq.pop();
            map.find(ret)->second->used = buffer_used;
        }
        pthread_mutex_unlock(mutex);
        return ret;
    }

    void free_buffer(char *buffer)
    {
        auto mutex = get_mutex();
        auto &map = get_pointer_map();
        auto &eq = get_empty_pool();
        pthread_mutex_lock(mutex);
        {
            map.find(buffer)->second->used = !buffer_used;
            eq.emplace(buffer);
        }
        pthread_mutex_unlock(mutex);
    }

    void destroy_buffer()
    {
        auto mutex = get_mutex();
        auto &map = get_pointer_map();

        pthread_mutex_lock(mutex);
        {
            for (auto &p : map) {
                delete p.second;
                delete[] p.first;
            }
        }
        pthread_mutex_unlock(mutex);
        pthread_mutex_destroy(mutex);
    }

    void init_buffer_pool(int buf_count)
    {
        resize_pool(buf_count);
        pthread_mutex_init(get_mutex(), nullptr);
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
