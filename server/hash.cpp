
#include "hash.h"
#include "athdns.h"
#include "logging.h"

#ifndef NDEBUG
#include "format.h"
#endif

#include <pthread.h>

#include <algorithm>

namespace hash
{
    namespace hash_fn
    {
        uint32_t hash_1(const CH *str)
        {
            const unsigned int seed = 131;
            unsigned int hash = 0;
            while (*str) {
                const uint32_t c = static_cast<uint32_t>(*str++);
                hash = hash * seed + c;
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

    hashtable::hashtable(size_type size)
    {
        total_size = size;
        saved = 0;
        lru_head = lru_end = nullptr;
        hash_size = size >> 1;
        pthread_mutex_init(&mutex, nullptr);
        lru_lock = lock_alloc.allocate(1);
        pthread_spin_init(lru_lock, PTHREAD_PROCESS_PRIVATE);
    }

    hashtable::~hashtable()
    {
        lock_alloc.destroy(lru_lock);
        lock_alloc.deallocate(lru_lock);
        std::for_each(container.begin(), container.end(), [&](auto &pair) {
            auto p = std::get<1>(pair);
            delete p;
        });
    }

    void hashtable::put(record_node *new_pointer)
    {
        if (unlikely(new_pointer == nullptr)) {
            return;
        }
        auto &entry = container;
        pthread_mutex_lock(&mutex);
        auto iter = entry.find(new_pointer->get_name());
        if (iter != entry.end()) {
            pthread_mutex_unlock(&mutex);
            delete new_pointer;
            return;
        } else {
            entry.insert({new_pointer->get_name(), new_pointer});
        }
        pthread_mutex_unlock(&mutex);

        pthread_spin_lock(lru_lock);
        if (unlikely(lru_head == nullptr)) {
            assert(lru_end == nullptr);
            lru_head = lru_end = new_pointer;
            new_pointer->lru_next = new_pointer->lru_prev = nullptr;
        } else {
            new_pointer->lru_prev = nullptr;
            new_pointer->lru_next = lru_head;
            lru_head->lru_prev = new_pointer;
            lru_head = new_pointer;
        }
        pthread_spin_unlock(lru_lock);
        saved++;
        if (saved > total_size) {
            pthread_spin_lock(lru_lock);
            assert(lru_end != nullptr);
            auto new_end = lru_end->lru_prev;
            auto old_end = lru_end;
            new_end->lru_next = nullptr;
            lru_end = new_end;
            saved--;
            pthread_spin_unlock(lru_lock);

            pthread_mutex_lock(&mutex);
            entry.erase(old_end->get_name());
            pthread_mutex_unlock(&mutex);

            DTRACE("LRU: remove old item {0}", *old_end);
            delete old_end;
        }
    }

    record_node *hashtable::get(const string &str)
    {
        return get(str.c_str());
    }

    record_node *hashtable::get(domain_name name)
    {
        auto &entry = container;
        pthread_mutex_lock(&mutex);
        auto pos = entry.find(name);
        pthread_mutex_unlock(&mutex);
        if (pos != entry.end()) {
            record_node *ret = std::get<1>(*pos);
            assert(lru_head != nullptr);
            pthread_spin_lock(lru_lock);
            lru_head->lru_prev = ret;
            if (ret->lru_prev != nullptr) {
                ret->lru_prev->lru_next = ret->lru_next;
            }
            if (ret->lru_next != nullptr) {
                ret->lru_next->lru_prev = ret->lru_prev;
            }
            ret->lru_prev = nullptr;
            ret->lru_next = lru_head;
            lru_head = ret;
            lru_end->lru_next = nullptr;
            pthread_spin_unlock(lru_lock);
            return ret;
        } else {
            return nullptr;
        }
    }

    size_t hashtable::get_saved() const
    {
#ifndef NDEBUG
        pthread_mutex_lock(&mutex);
        assert(container.size() == saved);
        pthread_mutex_unlock(&mutex);
#endif
        return saved;
    }

    bool hashtable::exists(const string &str) const
    {
        return exists(str.c_str());
    }

    bool hashtable::exists(domain_name name) const
    {
        pthread_mutex_lock(&mutex);
        auto pos = container.find(name);
        auto ret = pos != container.end();
        pthread_mutex_unlock(&mutex);
        return ret;
    }

    record_node *hashtable::get_last() const
    {
        return lru_head;
    }


}  // namespace hash
