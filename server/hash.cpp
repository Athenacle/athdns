
#include "hash.h"
#include "dnsserver.h"

#include <pthread.h>
#include <algorithm>

namespace hash
{
    namespace hash_fn
    {
        uint32_t hash_1(const CH *str)
        {
            const unsigned int seed = 131;
            unsigned int hash       = 0;
            while (*str) {
                const uint32_t c = static_cast<uint32_t>(*str++);
                hash             = hash * seed + c;
            }
            return (hash & 0x7FFFFFFF);
        }


        uint32_t hash_2(const CH *str)
        {
            unsigned int hash = 0;

            while (*str) {
                hash ^= ((hash << 7) ^ static_cast<uint32_t>(*str++) ^ (hash >> 3));
                if (*str == 0) {
                    break;
                }
                hash ^= (~((hash << 11) ^ static_cast<uint32_t>(*str++) ^ (hash >> 5)));
            }

            return (hash & 0x7FFFFFFF);
        }
    }  // namespace hash_fn


    void *record_node::operator new(size_t s)
    {
        return ::malloc(s);
    }

    void record_node::operator delete(void *p)
    {
        return ::free(p);
    }

    record_node::~record_node()
    {
        if (name != nullptr)
            utils::strfree(name);
    }

    record_node::record_node(domain_name n)
    {
        name     = utils::strdup(n);
        lru_prev = lru_next = nullptr;  //(record_node *)0xdeadbeef;
    }

    record_node::record_node()
    {
        name = nullptr;
    }

    bool record_node::domain_name_equal(domain_name n) const
    {
        return utils::strcmp(n, this->name) == 0;
    }


    bool record_node::operator==(const record_node &) const
    {
        return this->operator==(name);
    }

    bool record_node::operator==(domain_name name) const
    {
        return domain_name_equal(name);
    }

    record_node_A::record_node_A(domain_name name, ip_address &ip) : record_node(name), address(ip)
    {
    }

    bool record_node_A::operator==(const ip_address &ip) const
    {
        return address == ip;
    }

    bool record_node_A::operator==(const record_node_A &a) const
    {
        return domain_name_equal(a.get_name()) && this->operator==(a.address);
    }


    // class htable

    hashtable::hashtable(size_type size)
    {
        total_size = size;
        saved      = 0;
        lru_head = lru_end = nullptr;
        hash_size          = size >> 1;
        container          = alloc.allocate(hash_size);
        locks              = lock_alloc.allocate(hash_size);
        for (size_type i = 0; i < hash_size; i++) {
            alloc.construct(container + i);
            pthread_spin_init(locks + i, PTHREAD_PROCESS_PRIVATE);
        }
        lru_lock = lock_alloc.allocate(1);
        pthread_spin_init(lru_lock, PTHREAD_PROCESS_PRIVATE);
    }

    hashtable::~hashtable()
    {
        for (size_type i = 0; i < hash_size; i++) {
            auto &c = container[i];
            std::for_each(c.begin(), c.end(), [&](auto &p) {
                auto node = std::get<1>(p);
                delete node;
            });
            alloc.destroy(container + i);
            pthread_spin_destroy(locks + i);
            lock_alloc.destroy(locks + i);
        }
        lock_alloc.deallocate(locks, hash_size);
        alloc.deallocate(container, hash_size);

        lock_alloc.destroy(lru_lock);
        lock_alloc.deallocate(lru_lock);
    }

    void hashtable::put(record_node *new_pointer)
    {
        size_type l;
        auto &entry = get_container(new_pointer->get_name(), l);
        entry.insert({new_pointer->get_name(), new_pointer});

        pthread_spin_lock(lru_lock);
        if (unlikely(lru_head == nullptr)) {
            assert(lru_end == nullptr);
            lru_head = lru_end = new_pointer;
        } else {
            new_pointer->lru_next = lru_head;
            lru_head->lru_prev    = new_pointer;
            lru_head              = new_pointer;
        }
        pthread_spin_unlock(lru_lock);
        saved++;
        if (saved >= total_size) {
            pthread_spin_lock(lru_lock);
            assert(lru_end != nullptr);
            auto new_end      = lru_end->lru_prev;
            auto old_end      = lru_end;
            new_end->lru_next = nullptr;
            lru_end           = new_pointer;
            lru_end->lru_next = nullptr;
            saved--;
            pthread_spin_unlock(lru_lock);
            pthread_spin_lock(locks + l);
            entry.erase(lru_end->get_name());
            pthread_spin_unlock(locks + l);
            delete old_end;
        }
    }

    record_node *hashtable::get(const string &str)
    {
        return get(str.c_str());
    }

    record_node *hashtable::get(domain_name name)
    {
        size_type lock;
        auto &entry = get_container(name, lock);
        pthread_spin_lock(locks + lock);
        auto pos = entry.find(name);
        pthread_spin_unlock(locks + lock);
        if (pos != entry.end()) {
            record_node *ret = std::get<1>(*pos);
            assert(lru_head != nullptr);
            pthread_spin_lock(lru_lock);
            lru_head->lru_prev = ret;
            ret->lru_prev      = nullptr;
            ret->lru_next      = lru_head;
            lru_head           = ret;
            lru_end->lru_next  = nullptr;
            pthread_spin_unlock(lru_lock);
            return ret;
        } else {
            return nullptr;
        }
    }

    size_t hashtable::get_saved() const
    {
#ifndef NDEBUG
        size_t calc = 0;
        for (size_t i = 0; i < hash_size; i++) {
            calc += container[i].size();
        }
        assert(calc == saved);
#endif
        return saved;
    }

    bool hashtable::exists(const string &str) const
    {
        return exists(str.c_str());
    }

    bool hashtable::exists(domain_name name) const
    {
        auto &entry = get_container(name);
        auto pos    = entry.find(name);
        return pos != entry.end();
    }


}  // namespace hash
