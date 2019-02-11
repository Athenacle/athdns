#ifndef HASH_H
#define HASH_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dnsserver.h"

#include "single_link.h"

#include <cassert>
#include <cinttypes>
#include <forward_list>

namespace hash
{
    namespace hash_fn
    {
        uint32_t hash_1(const char *);
        uint32_t hash_2(const char *);
    }  // namespace hash_fn


    class lru_entry
    {
    public:
        lru_entry *lru_prev;
        lru_entry *lru_next;

        lru_entry()
        {
            lru_next = lru_prev = nullptr;
        }
    };


    template <class Key>
    class hash_entry
    {
    public:
        using const_key_reference = const Key &;
        using hash_entry_type     = hash_entry<Key>;

        hash_entry_type *lru_prev;
        hash_entry_type *lru_next;

    private:
        uint32_t hc_1;
        uint32_t hc_2;

    public:
        using node_ptr = hash_entry<Key> *;

    public:
        uint32_t get_hash_1() const
        {
            return hc_1;
        }

        uint32_t get_hash_2() const
        {
            return hc_2;
        }

        virtual ~hash_entry() {}

        hash_entry()
        {
            hc_1 = hc_2 = 0;
        }

        hash_entry(const_key_reference key)
        {
            hc_1     = hash_fn::hash_1(key);
            hc_2     = hash_fn::hash_2(key);
            lru_prev = lru_next = nullptr;
        }

        bool hc_2_equal(const_key_reference key) const
        {
            return hc_2 == hash_fn::hash_2(key);
        }

        bool same(uint32_t hc1, uint32_t hc2) const
        {
            return hc_1 == hc1 && hc2 == hc_2;
        }

        bool same(const_key_reference key) const
        {
            return hc_1 == hash_fn::hash_1(key) && hc_2 == hash_fn::hash_2(key);
        }

        bool operator==(const_key_reference key) const
        {
            return hc_1 == hash_fn::hash_1(key) && hc_2 == hash_fn::hash_2(key);
        }
    };


    class hash_entry_A : public hash_entry<const char *>
    {
        ip_address __address;

    public:
        bool operator==(const hash_entry_A &a) const
        {
            return __address == a.__address;
        }

        bool operator==(const ip_address &ip) const
        {
            return __address == ip;
        }

        hash_entry_A(const char *domain, const ip_address &ip)
            : hash_entry<const char *>(domain), __address(ip)
        {
        }

        hash_entry_A() : hash_entry<const char *>(""), __address(0u) {}
    };


    template <class K, class T>
    class table_entry
    {
        using container_type      = utils::single_link<T>;
        using const_reference     = const T &;
        using reference           = T &;
        using const_key_reference = const K &;
        using value_pointer       = T *;

        using container_node_type     = utils::single_link_node<T>;
        using container_node_iterator = typename utils::single_link<T>::forward_iterator;

        using container_node_type_pointer = container_node_type *;
        using hash_entry_type             = typename T::hash_entry_type;

        container_type container;

    public:
        int get_saved() const
        {
            return container.get_saved();
        }

        value_pointer put(const_reference cr)
        {
            return container.append(cr);
        }

        bool exists(const_key_reference key) const
        {
            for (auto &iter : container) {
                if (iter.same(key)) {
                    return true;
                }
            }
            return false;
        }

        value_pointer get(const_key_reference key, reference value)
        {
            container_node_iterator iter(container.begin());
            for (; iter != container.end(); iter.next()) {
                if (iter->hc_2_equal(key)) {
                    value = *iter;
                    return iter.address();
                }
            }
            return nullptr;
        }

        void remove(uint32_t hc1, uint32_t hc2)
        {
            container_node_iterator iter(container.begin());

            for (; iter != container.end(); iter.next()) {
                if (iter->same(hc1, hc2)) {
                    container.remove(iter);
                    return;
                }
            }
            assert(false);
        }
    };


    template <class K,
              class T,
              class Entry     = table_entry<K, T>,
              class Allocator = std::allocator<Entry>>
    class hash_table
    {
        using size_type       = size_t;
        using reference       = T &;
        using const_reference = T &;
        using pointer         = T *;

        using entry_pointer   = Entry *;
        using entry_reference = Entry &;

        using key_reference       = K &;
        using const_key_reference = const K &;

        using node_ptr = typename T::node_ptr;

        using lru_pointer = typename T::hash_entry_type *;

        struct lru_tuple {
            using pointer_type = typename T::hash_entry_type *;

            lru_pointer pointer;
            uint32_t hashcode_1;
            uint32_t hashcode_2;

            lru_tuple()
            {
                pointer    = nullptr;
                hashcode_1 = hashcode_2 = 0;
            }
            bool operator==(lru_pointer p) const
            {
                return pointer == p;
            }
            bool operator==(lru_tuple &entry) const
            {
                return pointer == entry.pointer;
            }

            lru_tuple &operator=(pointer_type p)
            {
                pointer    = p;
                hashcode_1 = p->get_hash_1();
                hashcode_2 = p->get_hash_2();
                return *this;
            }
            void set(pointer_type p, uint32_t hc, uint32_t hc2)
            {
                pointer    = p;
                hashcode_1 = hc;
                hashcode_2 = hc2;
            }
            T *get_pointer() const
            {
                return pointer;
            }
        };

    private:
        entry_pointer table;
        size_type ht_size;
        size_type table_size;
        size_type saved;

        Allocator alloc;

        node_ptr head;
        node_ptr tail;

        lru_tuple lru_head;
        lru_tuple lru_end;

        entry_reference get_entry(const_key_reference key)
        {
            uint32_t hc = hash_fn::hash_1(key);
            auto offset = hc % table_size;
            return table[offset];
        }

        void lru_remove_last()
        {
            auto last = lru_end;
            auto prev = dynamic_cast<lru_pointer>(lru_end.pointer->lru_prev);

            uint32_t hc = last.hashcode_1;
            auto offset = hc % table_size;

            prev->lru_next = nullptr;
            lru_end.set(prev, prev->get_hash_1(), prev->get_hash_2());

            table[offset].remove(last.hashcode_1, last.hashcode_2);
        }

    public:
        hash_table(size_type size) : lru_head(), lru_end()
        {
            head = tail = nullptr;
            saved       = 0;

            const static auto is_prime = [=](size_type num) {
                if (num <= 1)
                    return false;
                if (num % 2 == 0 && num > 2)
                    return false;
                for (size_type i = 3; i < num / 2; i += 2) {
                    if (num % i == 0)
                        return false;
                }
                return true;
            };

            const static auto pre_prime = [=](size_type num) {
                static const size_type default_number = 509;
                for (; num > default_number; num--) {
                    if (is_prime(num))
                        return num;
                }
                return default_number;
            };

            ht_size    = size - 1;
            table_size = pre_prime(size >> 1);
            table      = alloc.allocate(table_size);
            for (size_type i = 0; i < table_size; i++) {
                alloc.construct(table + i);
            }
        }

        ~hash_table()
        {
            for (size_type i = 0; i < table_size; i++) {
                alloc.destroy(table + i);
            }
            alloc.deallocate(table, table_size);
        }

        bool exists(const_key_reference key)
        {
            return get_entry(key).exists(key);
        }

        bool get(const_key_reference key, reference value)
        {
            auto &entry = get_entry(key);
            auto status = entry.get(key, value);
            if (status != nullptr) {
                auto value_pointer = status;
                auto next          = value.lru_next;
                if (next != nullptr) {
                    next->lru_prev = value.lru_prev;
                }
                value.lru_next = lru_head.pointer;
                lru_head.set(
                    value_pointer, value_pointer->get_hash_1(), value_pointer->get_hash_2());
            }
            return status;
        }

        void put(const_key_reference kr, const_reference cr)
        {
            pointer the = get_entry(kr).put(cr);
            if (lru_head == nullptr) {
                if (lru_end == nullptr) {
                    lru_head = lru_end = the;
                } else {
                    assert(false);
                }
            } else {
                auto old_lru_head      = lru_head.pointer;
                old_lru_head->lru_prev = the;
                the->lru_next          = old_lru_head;
                the->lru_prev          = nullptr;
                lru_head.set(the, the->get_hash_1(), the->get_hash_2());
            }
            saved++;
            if (saved > ht_size) {
                lru_remove_last();
                saved--;
            }
        }

        int get_saved() const
        {
            int s = 0;

            for (size_type i = 0; i < table_size; i++) {
                s += table[i].get_saved();
            }

            return s;
        }
    };

}  // namespace hash


#endif
