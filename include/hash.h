/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// hash.h: hashtable class

#ifndef HASH_H
#define HASH_H

#include "athdns.h"
#include "record.h"
#include "utils.h"

#include <cassert>
#include <cinttypes>
#include <forward_list>
#include <unordered_map>

namespace hash
{
    namespace hash_fn
    {
        uint32_t hash_1(const char *);
        uint32_t hash_2(const char *);
    }  // namespace hash_fn

    class hashtable;

    namespace alloc
    {
        template <class T>
        struct allocator {
            using value_type = T;
            using pointer = value_type *;
            using size_type = size_t;

        public:
            static pointer allocate(size_type count)
            {
                return reinterpret_cast<T *>(::malloc(sizeof(T) * count));
            }

            template <class... Args>
            static pointer construct(T *p, Args &&... args)
            {
                return new (p) T(std::forward<Args>(args)...);
            }

            static pointer construct(T *p)
            {
                return new (p) T;
            }

            static void destroy(T *p)
            {
                p->~T();
            }

            static void deallocate(T *p, size_type = 1)
            {
                ::free((void *)(p));
            }
        };
    }  // namespace alloc


    class hashtable
    {
        struct unordered_map_hash {
            std::size_t operator()(domain_name name) const
            {
                return hash::hash_fn::hash_2(name);
            }
        };

        struct unordered_map_equal {
            bool operator()(const domain_name &lhs, const domain_name &rhs) const
            {
                return utils::str_equal(lhs, rhs);
            }
        };

        using domain_name = const char *;

        using record_type = record_node;
        using pointer = record_node *;
        using reference = record_type &;
        using const_reference = const record_type &;

        using container_type =
            std::unordered_map<domain_name, hash_node *, unordered_map_hash, unordered_map_equal>;

        using container_pointer = container_type *;
        using container_reference = container_type &;

        using size_type = size_t;

    private:
        container_type container;

        hash_node *lru_head;
        hash_node *lru_end;

        size_type total_size;
        size_type hash_size;

        utils::atomic_number<size_type> saved;

        mutable pthread_rwlock_t table_rwlock;
        mutable pthread_spinlock_t lru_lock;

    private:
    public:
        hashtable(size_type size);
        ~hashtable();

        bool put(record_node *);

        pointer get(const string &);
        pointer get(domain_name);

        bool exists(domain_name) const;
        bool exists(const string &) const;

        size_type get_saved() const;

        pointer get_last() const;
    };

}  // namespace hash


#endif
