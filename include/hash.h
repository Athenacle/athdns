#ifndef HASH_H
#define HASH_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dnsserver.h"

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

    using domain_name = const char *;

    class hashtable;

    namespace alloc
    {
        template <class T>
        struct allocator {
            using value_type = T;
            using pointer    = value_type *;
            using size_type  = size_t;

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

    class record_node
    {
        friend class hashtable;

        domain_name name;

        record_node *lru_next;
        record_node *lru_prev;

    protected:
        bool domain_name_equal(domain_name) const;

    public:
        record_node();
        record_node(domain_name);
        virtual ~record_node();

        domain_name get_name() const
        {
            return name;
        }

        bool operator==(const record_node &) const;

        bool operator==(domain_name) const;

        void *operator new(size_t);

        void operator delete(void *);
    };

    class record_node_A : public record_node
    {
        ip_address address;

    public:
        record_node_A();
        record_node_A(domain_name, ip_address &);
        bool operator==(const record_node_A &) const;
        bool operator==(const ip_address &) const;
    };

    class hashtable
    {
        struct unordered_map_hash {
            std::size_t operator()(domain_name name) const
            {
                return hash::hash_fn::hash_2(name);
            }
        };

        struct unordered_map_equal {
            bool operator()(const domain_name lhs, const domain_name &rhs) const
            {
                return utils::strcmp(lhs, rhs) == 0;
            }
        };

        using domain_name = const char *;

        using record_type     = record_node;
        using pointer         = record_node *;
        using reference       = record_type &;
        using const_reference = const record_type &;
        using const_pointer   = const record_type *;

        using container_type =
            std::unordered_map<domain_name, record_node *, unordered_map_hash, unordered_map_equal>;

        using lock_type    = pthread_spinlock_t;
        using lock_pointer = lock_type *;

        using container_pointer   = container_type *;
        using container_reference = container_type &;

        using size_type = size_t;

    private:
        container_pointer container;
        lock_pointer locks;
        lock_pointer lru_lock;

        pointer lru_head;
        pointer lru_end;

        size_type total_size;
        size_type hash_size;
        size_type saved;


    private:
        container_reference get_container(domain_name name) const
        {
            auto hc_1   = hash::hash_fn::hash_1(name);
            auto offset = hc_1 % hash_size;
            return container[offset];
        }

        container_reference get_container(domain_name name, size_type &off) const
        {
            auto hc_1   = hash::hash_fn::hash_1(name);
            auto offset = hc_1 % hash_size;
            off         = offset;
            return container[offset];
        }

        alloc::allocator<container_type> alloc;
        alloc::allocator<lock_type> lock_alloc;

    public:
        hashtable(size_type size);
        ~hashtable();

        void put(record_node *);

        pointer get(const string &);
        pointer get(domain_name);

        bool exists(domain_name) const;
        bool exists(const string &) const;

        size_type get_saved() const;
    };

}  // namespace hash


#endif
