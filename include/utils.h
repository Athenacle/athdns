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
#include "fmt/core.h"
#include "fmt/time.h"

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
    char *get_buffer(size_t = 0);
    void free_buffer(char *, size_t);
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

    inline bool str_equal(const char *s1, const char *s2)
    {
        auto l1 = strlen(s1);
        auto l2 = strlen(s2);
        if (likely(l1 != l2)) {
            return false;
        } else {
            return strncmp(s1, s2, l1) == 0;
        }
    }

    inline char *str_dump(const char *s)
    {
        auto length = strlen(s) + 1;
        auto ret = new char[length];
        strncpy(ret, s, length);
        return ret;
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
        pthread_mutex_t *mutex;
        std::queue<pointer> empty_queue;
        std::unordered_map<pointer, __entry_map> pool_map;
#ifndef NDEBUG
        atomic_int allocated_count;
        atomic_int max_allocated;
        atomic_int deallocated_count;
#endif
        void lock() const
        {
            pthread_mutex_lock(mutex);
        }

        void unlock() const
        {
            pthread_mutex_unlock(mutex);
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
            pthread_mutex_destroy(mutex);
            delete mutex;
        }

        allocator_pool(size_t size)
#ifndef NDEBUG
            : allocated_count(0), max_allocated(0)
#endif
        {
            mutex = new pthread_mutex_t;
            pthread_mutex_init(mutex, nullptr);
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

        void for_each(std::function<void(const pointer)>) {}

        template <unsigned int _N = N, class... Args>
        std::enable_if_t<(_N >= 2), pointer> allocate() const
        {
            return new value_type[N];
        }

        template <unsigned int _N = N, class... Args>
        std::enable_if_t<(_N == 1), pointer> allocate(Args... __args) const
        {
            return new value_type(std::forward<Args>(__args)...);
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
    };

#ifdef CLOCK_REALTIME_COARSE
#define ATHDNS_CLOCK_GETTIME_FLAG CLOCK_REALTIME_COARSE
#else
#define ATHDNS_CLOCK_GETTIME_FLAG CLOCK_REALTIME
#endif

    class time_object
    {
    public:
        struct timespec t;

        time_object();

        ~time_object() {}

        time_object(const time_object &);

        void operator()();

        static uint64_t diff_to_ns(const time_object &, const time_object &);

        static double diff_to_us(const time_object &, const time_object &);

        static double diff_to_ms(const time_object &, const time_object &);

        static void sleep_for_seconds(uint32_t);

        time_object &operator=(time_object &&);

        bool operator==(const time_object &) const;
    };
}  // namespace utils

namespace fmt
{
    template <>
    struct formatter<utils::time_object> {
        template <class PC>
        constexpr auto parse(PC &ctx)
        {
            return ctx.begin();
        }

        template <class T>
        auto format(const utils::time_object &__t, T &ctx)
        {
            auto time_buffer = fmt::format("{:%Y-%m-%d %H:%M:%S}", *std::localtime(&__t.t.tv_sec));
            return format_to(ctx.begin(), "{0}:{1:=06d}", time_buffer, __t.t.tv_nsec / 1000);
        }
    };
}  // namespace fmt

#endif
