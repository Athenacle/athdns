
#ifndef UTILS_H
#define UTILS_H

#include "dnsserver.h"

#include <pthread.h>

#include <cstring>      // memset
#include <type_traits>  // std::enable_if_t

namespace utils
{
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
        pthread_spinlock_t lock;

    public:
        ~atomic_number() {}

        explicit atomic_number(T v = 0) : lock()
        {
            pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE);
            value = v;
        }

        T get()
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

        operator T()
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

    long read_rss();

}  // namespace utils


#endif
