
#include "dnsserver.h"
#include "logging.h"

#include <unistd.h>
#include <cctype>
#include <cstdio>

#include <random>

using namespace utils;
using std::vector;

namespace
{
    int check_all_digit(const string &part)
    {
        return std::stoi(part);
    }

    inline std::vector<char *> &get_pool()
    {
        static std::vector<char *> pool;
        return pool;
    }

    inline utils::bit_container &get_bitmap()
    {
        static utils::bit_container container(512);
        return container;
    }

    inline pthread_mutex_t *get_mutex()
    {
        static pthread_mutex_t mutex;
        return &mutex;
    }

    inline std::unordered_map<char *, size_t> &get_pointer_map()
    {
        static std::unordered_map<char *, size_t> map;
        return map;
    }

    size_t find_first_false(const utils::bit_container &bitmap)
    {
        auto s = bitmap.size();
        for (size_t i = 0; i < s; i++) {
            if (!bitmap.test(i)) {
                return i;
            }
        }
        return -1u;
    }

    void resize_pool(int new_size)
    {
        auto &bs = get_bitmap();
        bs.resize(new_size);
        auto &vec = get_pool();
        vec.reserve(new_size);
        for (int i = 0; i < new_size; i++) {
            vec[i] = new char[recv_buffer_size];
        }
    }


}  // namespace


namespace utils
{
    char *get_buffer()
    {
        auto &vec = get_pool();
        auto &bitmap = get_bitmap();
        auto mutex = get_mutex();
        auto &pointer_map = get_pointer_map();
        pthread_mutex_lock(mutex);
        size_t offset = find_first_false(bitmap);
        if (offset == -1u) {
            resize_pool(bitmap.size() * 2);
            offset = find_first_false(bitmap);
        }
        auto ret = vec[offset];
        bitmap.set(offset, true);
        pointer_map.insert({ret, offset});
        pointer_map[ret] = offset;

        pthread_mutex_unlock(mutex);
        return ret;
    }  // namespace utils

    void free_buffer(char *buffer)
    {
        auto &bitmap = get_bitmap();
        auto mutex = get_mutex();
        auto &map = get_pointer_map();

        pthread_mutex_lock(mutex);
        auto p = map.find(buffer);
        assert(p != map.end());
        bitmap.set(p->second, false);
        pthread_mutex_unlock(mutex);
    }

    void destroy_buffer()
    {
        auto &vec = get_pool();
        auto mutex = get_mutex();

        pthread_mutex_lock(mutex);
        for (auto &p : vec) {
            delete[] p;
        }
        pthread_mutex_unlock(mutex);

        pthread_mutex_destroy(mutex);
    }


    void init_buffer_pool(int buf_count)
    {
        auto &vec = get_pool();
        auto &bitmap = get_bitmap();
        auto &map = get_pointer_map();
        map.reserve(buf_count);
        vec.reserve(buf_count + 1);
        bitmap.resize(buf_count);
        for (int i = 0; i < buf_count; i++) {
            auto buf = new char[recv_buffer_size];
            vec.emplace_back(buf);
            bitmap.set(i, false);
        }
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

}  // namespace utils

namespace logging
{
    void set_default_level(log_level ll)
    {
        auto level = spdlog::level::debug;
        switch (ll) {
            case utils::LL_TRACE:
                level = spdlog::level::debug;
                break;
            case utils::LL_ERROR:
                level = spdlog::level::err;
                break;
            case utils::LL_WARNING:
                level = spdlog::level::warn;
                break;
            case utils::LL_INFO:
                level = spdlog::level::info;
                break;
            case utils::LL_OFF:
                level = spdlog::level::off;
                break;

            default:
                level = spdlog::level::info;
                break;
        }
        spdlog::set_level(level);
    }

    void init_logging() {}

}  // namespace logging
