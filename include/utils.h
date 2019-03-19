/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// utils.h: utilities header

#ifndef UTILS_H
#define UTILS_H

#include "athdns.h"

#include <pthread.h>

#include <algorithm>
#include <cstring>  // memset
#include <functional>
#include <queue>
#include <type_traits>  // std::enable_if_t
#include <unordered_map>

namespace utils
{
    long read_rss();
    bool check_uv_return_status(int, const char *);

    void init_buffer_pool(size_t);
    char *get_buffer();
    void free_buffer(char *);
    void destroy_buffer();
#ifndef NDEBUG
    size_t get_max_buffer_allocate();
    size_t get_current_buffer_allocate();
#endif

    void config_system(int, CH *const[]);

    void split(std::vector<string> &, const CH *, const CH);

#ifdef HAVE_DOH_SUPPORT
    char *encode_base64(const void *, size_t);
    char *encode_base64(const char *);
#endif

    template <class T>
    T *str_allocate(size_t count)
    {
        return reinterpret_cast<T *>(::malloc(sizeof(T) * count));
    }


    template <class C>
    size_t strlen(const C *const str)
    {
        return std::char_traits<C>::length(str);
    }

    template <class C>
    int strcmp(const C *const s1, const C *const s2)
    {
        auto sl1 = strlen(s1);
        auto sl2 = strlen(s2);
        return std::char_traits<C>::compare(s1, s2, sl1 > sl2 ? sl2 : sl1);
    }

    template <class C>
    void strcpy(C *to, const C *from)
    {
        std::char_traits<C>::copy(to, from, strlen(from));
    }

    template <class C>
    C *strdup(const C *const str)
    {
        const auto len = strlen(str);
        auto ret = str_allocate<C>(len + 1);
        strcpy(ret, str);
        std::char_traits<C>::assign(ret[len], 0);
        return ret;
    }

    template <class C>
    void strfree(const C *str)
    {
        if (likely(str != nullptr)) {
            ::free((void *)str);
        }
    }

    template <class T>
    T *make(const T *pointer)
    {
        auto ret = ::malloc(sizeof(T));
        std::memcpy(ret, pointer, sizeof(T));
        return reinterpret_cast<T *>(ret);
    }

    template <class T>
    void destroy(const T *const p)
    {
        if (likely(p != nullptr)) {
            ::free((void *)p);
        }
    }

    template <class T, class _ = std::enable_if_t<std::is_integral<T>::value, int>>
    class atomic_number
    {
    private:
        T value;
        mutable pthread_spinlock_t lock;

    public:
        ~atomic_number() {}

        explicit atomic_number(T v = 0) : lock()
        {
            pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE);
            value = v;
        }

        T get() const
        {
            pthread_spin_lock(&lock);
            auto ret = value;
            pthread_spin_unlock(&lock);
            return ret;
        }

        T reset(T v)
        {
            pthread_spin_lock(&lock);
            value = v;
            pthread_spin_unlock(&lock);
            return v;
        }

        operator T() const
        {
            return get();
        }

        T operator--()
        {
            pthread_spin_lock(&lock);
            value -= 1;
            auto ret = value;
            pthread_spin_unlock(&lock);
            return ret;
        }

        T operator--(int)
        {
            pthread_spin_lock(&lock);
            auto ret = value;
            value -= 1;
            pthread_spin_unlock(&lock);
            return ret;
        }

        T operator++()
        {
            pthread_spin_lock(&lock);
            value += 1;
            auto ret = value;
            pthread_spin_unlock(&lock);
            return ret;
        }

        T operator++(int)
        {
            pthread_spin_lock(&lock);
            auto ret = value;
            value += 1;
            pthread_spin_unlock(&lock);
            return ret;
        }

        T operator=(T v)
        {
            return v;
        }
    };

    using atomic_int = atomic_number<int>;
    using atomic_uint16 = atomic_number<uint16_t>;

    class bit_container
    {
        size_t bc_size;
        size_t buffer_size;
        uint32_t *buffer;

    public:
        size_t size() const
        {
            return bc_size;
        }

        bit_container(size_t total)
        {
            bc_size = total;
            buffer_size = bc_size + 32;
            buffer = new uint32_t[buffer_size / 32];
            std::memset(buffer, 0, buffer_size / 32);
        }

        ~bit_container()
        {
            delete[] buffer;
        }

        void set(size_t offset, bool value)
        {
            size_t int_offset = offset / 32;
            size_t bit_offset = offset % 32;
            uint32_t mask = 1 << bit_offset;
            if (value) {
                // set to 1
                *(buffer + int_offset) = *(buffer + int_offset) | mask;
            } else {
                mask = ~mask;
                *(buffer + int_offset) &= mask;
            }
        }

        bool test(size_t offset) const
        {
            size_t int_offset = offset / 32;
            size_t bit_offset = offset % 32;
            uint32_t v = *(buffer + int_offset) >> bit_offset;
            return (v & 1) == 1;
        }

        void resize(size_t new_size)
        {
            if (new_size < bc_size) {
                return;
            }
            auto old_buffer_size = buffer_size;
            bc_size = new_size;
            buffer_size = bc_size + 32;
            auto old_buffer = buffer;
            buffer = new uint32_t[buffer_size / 32];
            std::memset(buffer, 0, buffer_size / 32);
            std::memcpy(buffer, old_buffer, old_buffer_size / 32);
            delete[] old_buffer;
        }
    };

    template <class T, unsigned int N = 1>
    class allocator_pool
    {
        static_assert(N >= 0, "N parameter cannot be zero. Single Object is 1");

        using value_type = T;
        using pointer = T *;

#ifndef ATHDNS_MEM_DEBUG
    private:
        struct __entry_map {
            bool used;
        };
        pthread_spinlock_t *mutex;
        std::queue<pointer> empty_queue;
        std::unordered_map<pointer, __entry_map> pool_map;
#ifndef NDEBUG
        atomic_int allocated_count;
        atomic_int max_allocated;
        atomic_int deallocated_count;
#endif
        void lock() const
        {
            pthread_spin_lock(mutex);
        }

        void unlock() const
        {
            pthread_spin_unlock(mutex);
        }

        void resize(size_t s)
        {
            auto os = pool_map.size();
            if (os >= s) {
                return;
            } else {
                for (size_t i = os; i < s; ++i) {
                    auto nv = reinterpret_cast<pointer>(malloc(N * sizeof(value_type)));
                    new (nv) value_type();
                    empty_queue.emplace(nv);
                    pool_map.insert({nv, __entry_map()});
                }
            }
        }

        pointer get_pointer()
        {
            lock();
            if (likely(empty_queue.empty())) {
                resize(pool_map.size() << 1);
            }

            auto ret = empty_queue.front();
            empty_queue.pop();
            auto itor = pool_map.find(ret);
            itor->second.used = true;
            unlock();
            return ret;
        }

        void free_pointer(pointer p)
        {
            lock();
            pool_map.find(p)->second.used = false;
            empty_queue.emplace(p);
            unlock();
        }

    public:
        ~allocator_pool()
        {
            lock();
            std::for_each(pool_map.begin(), pool_map.end(), [](auto &p) {
                auto ptr = p.first;
                free(ptr);
            });
            unlock();
            pthread_spin_destroy(mutex);
            delete mutex;
        }

        allocator_pool(size_t size)
#ifndef NDEBUG
            : allocated_count(0), max_allocated(0)
#endif
        {
            mutex = new pthread_spinlock_t;
            pthread_spin_init(mutex, PTHREAD_PROCESS_PRIVATE);
            resize(size);
        }

        template <unsigned int _N = N>
        typename std::enable_if_t<(_N >= 2), pointer> allocate()
        {
#ifndef NDEBUG
            allocated_count++;
#endif
            pointer ret = get_pointer();
            return ret;
        }

        template <unsigned int _N = N, class... Args>
        std::enable_if_t<(_N == 1), pointer> allocate(Args... __args)
        {
#ifndef NDEBUG
            allocated_count++;
#endif
            pointer ret = get_pointer();
            new (ret) value_type(std::forward<Args>(__args)...);
            return ret;
        }

        void deallocate(pointer p)
        {
#ifndef NDEBUG
            deallocated_count++;
            auto current = allocated_count - deallocated_count;
            if (current > max_allocated) {
                max_allocated.reset(current);
            }
#endif
            p->~value_type();
            free_pointer(p);
        }

        size_t get_current_allocated() const
        {
            lock();
            auto ret = pool_map.size() - empty_queue.size();
            unlock();
            return ret;
        }

#ifndef NDEBUG
        int get_max_allocated()
        {
            return max_allocated;
        }
#endif
        void for_each(std::function<void(const pointer)> cb)
        {
            lock();
            auto begin = pool_map.begin();
            auto end = pool_map.end();
            for (; begin != end; ++begin) {
                cb(begin->first);
            }
            unlock();
        }

#else
    public:
        allocator_pool(int) {}

        ~allocator_pool() {}

        template <unsigned int _N = N, class... Args>
        std::enable_if_t<(_N >= 2), pointer> allocate() const
        {
            return new value_type[N];
        }

        template <unsigned int _N = N, class... Args>
        std::enable_if_t<(_N == 1), pointer> allocate(const Args &... __args) const
        {
            return new value_type(__args...);
        }

        template <unsigned int _N = N>
        void deallocate(std::enable_if_t<_N == 1, pointer> p) const
        {
            delete p;
        }

        template <unsigned int _N = N>
        void deallocate(std::enable_if_t<_N >= 2, pointer> p) const
        {
            delete[] p;
        }

        size_t get_current_allocated() const
        {
            return 0;
        }

#ifndef NDEBUG
        int get_max_allocated()
        {
            return 0;
        }
#endif  // NDEBUG

#endif  // ATHDNS_MEM_DEBUG
    };  // namespace utils
}  // namespace utils

#endif
