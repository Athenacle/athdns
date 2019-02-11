
#include "test.h"

#include "hash.h"

#include <algorithm>
#include <tuple>
#include <vector>

using namespace hash;
using namespace std;
using namespace test;

namespace
{
    template <class K, class V>
    struct CacheNode_ {
        using this_type = CacheNode_<K, V>;
        using pointer   = this_type *;

        K key;
        V value;

        pointer next;
        pointer pre;
    };

    template <class K, class V>
    class LRUCache
    {
        using CacheNode = CacheNode_<K, V>;

    public:
        LRUCache(int cache_size = 10)
        {
            cache_size_             = cache_size;
            cache_real_size_        = 0;
            p_cache_list_head       = new CacheNode();
            p_cache_list_near       = new CacheNode();
            p_cache_list_head->next = p_cache_list_near;
            p_cache_list_head->pre  = NULL;
            p_cache_list_near->pre  = p_cache_list_head;
            p_cache_list_near->next = NULL;
        }
        ~LRUCache()
        {
            CacheNode *p;
            p = p_cache_list_head->next;
            while (p != NULL) {
                delete p->pre;
                p = p->next;
            }

            delete p_cache_list_near;
        }

        int size() const
        {
            return cache_real_size_;
        }


        bool get(const K &key)
        {
            CacheNode *p = p_cache_list_head->next;
            while (p->next != NULL) {
                if (p->key == key)  //catch node
                {
                    detachNode(p);
                    addToFront(p);
                    return true;
                }
                p = p->next;
            }
            return false;
        }

        bool get(const K &key, V &value)
        {
            CacheNode *p = p_cache_list_head->next;
            while (p->next != NULL) {
                if (p->key == key)  //catch node
                {
                    detachNode(p);
                    addToFront(p);
                    value = p->value;
                    return true;
                }
                p = p->next;
            }
            return false;
        }

        bool put(const K &key, const V &value)
        {
            CacheNode *p = p_cache_list_head->next;
            while (p->next != NULL) {
                if (p->key == key)  //catch node
                {
                    p->value = value;
                    get(key);
                    return true;
                }
                p = p->next;
            }


            if (cache_real_size_ >= cache_size_) {
                cout << "free" << endl;
                p = p_cache_list_near->pre->pre;
                delete p->next;
                p->next                = p_cache_list_near;
                p_cache_list_near->pre = p;
            }

            p = new CacheNode();

            if (p == NULL)
                return false;

            addToFront(p);
            p->key   = key;
            p->value = value;

            cache_real_size_++;

            return true;
        }

    private:
        int cache_size_;
        int cache_real_size_;
        CacheNode *p_cache_list_head;
        CacheNode *p_cache_list_near;

        void detachNode(CacheNode *node)
        {
            node->pre->next = node->next;
            node->next->pre = node->pre;
        }

        void addToFront(CacheNode *node)
        {
            node->next                   = p_cache_list_head->next;
            p_cache_list_head->next->pre = node;
            p_cache_list_head->next      = node;
            node->pre                    = p_cache_list_head;
        }
    };

}  // namespace

const int rlen = 20;

TEST(hash_table, lru_test)
{
    const int count = 2000;
    LRUCache<const CH *, hash_entry_A> cache(count);
    hash_table<const CH *, hash_entry_A> table(count);
    vector<tuple<const CH *, ip_address> > vec;

    vec.reserve(count * 2);

    for (int i = 0; i < count - 1; i++) {
        auto *str = random_string(rlen);
        ip_address ip(random_value());
        hash_entry_A entry(str, ip);
        table.put(str, entry);
        cache.put(str, entry);
        vec.emplace_back(make_tuple(str, ip));
    }

    EXPECT_EQ(cache.size(), table.get_saved()) << cache.size();


    for (auto &iter : vec) {
        auto &key   = std::get<0>(iter);
        auto &value = std::get<1>(iter);
        hash_entry_A table_the;
        hash_entry_A cache_the;
        EXPECT_TRUE(cache.get(key, cache_the));
        EXPECT_TRUE(table.get(key, table_the));
        EXPECT_TRUE(cache_the == table_the);
        EXPECT_TRUE(cache_the == value);
    }

    for (int i = 0; i < count - 1; i++) {
        auto *str = random_string(rlen);
        ip_address ip(random_value());
        hash_entry_A entry(str, ip);
        vec.emplace_back(make_tuple(str, ip));
    }

    for (size_t i = 0; i < vec.size(); i++) {
        auto iter         = vec[i];
        auto &key         = std::get<0>(iter);
        bool cache_exists = cache.get(key);
        bool table_exists = table.exists(key);
        EXPECT_EQ(cache_exists, table_exists);
    }

    int cycle_times = random_value() % 10000 + 5000;

    for (int i = 0; i < cycle_times; i++) {
        auto iter   = vec[random_value() % vec.size()];
        auto &key   = std::get<0>(iter);
        auto &value = std::get<1>(iter);
        hash_entry_A table_the;
        hash_entry_A cache_the;
        bool cache_exists = cache.get(key, cache_the);
        bool table_exists = table.get(key, table_the);
        EXPECT_EQ(cache_exists, table_exists);
        if (cache_exists && table_exists) {
            EXPECT_EQ(table_the, cache_the);
            EXPECT_EQ(cache_the, value);
        }
    }

    EXPECT_EQ(cache.size(), table.get_saved()) << cache.size();

    for (auto &iter : vec) {
        auto ptr = std::get<0>(iter);
        delete[] ptr;
    }
}


TEST(hash_table, hash_test)
{
    const int count = 3000;

    hash_table<const CH *, hash_entry_A> table(count);
    vector<tuple<const CH *, ip_address> > vec;

    vec.reserve(count);

    for (int i = 0; i < count - 1; i++) {
        auto *str = random_string(rlen);
        ip_address ip(random_value());
        hash_entry_A entry(str, ip);
        table.put(str, entry);
        vec.emplace_back(make_tuple(str, ip));
    }

    table.get_saved();

    for (auto &iter : vec) {
        auto &key   = std::get<0>(iter);
        auto &value = std::get<1>(iter);
        hash_entry_A the;
        EXPECT_TRUE(table.get(key, the));
        EXPECT_TRUE(the == value);
    }

    for (int i = 0; i < 100; i++) {
        auto p         = random_string(rlen);
        auto pos       = std::find_if(vec.cbegin(), vec.cend(), [&](auto &ref) {
            auto &ptr = std::get<0>(ref);
            return utils::strcmp(ptr, p) == 0;
        });
        auto vec_exist = pos == vec.cend();
        EXPECT_EQ(!vec_exist, table.exists(p));
        delete[] p;
    }

    for (auto &iter : vec) {
        auto ptr = std::get<0>(iter);
        delete[] ptr;
    }
}
