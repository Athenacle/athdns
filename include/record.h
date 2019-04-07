/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// record.h: record class used for hashtable header file

#ifndef RECORD_H
#define RECORD_H

#include "fmt/format.h"

#include "athdns.h"
#include "utils.h"

using domain_name = const char *;

enum class reply_type { NONE, ANSWER, AUTHORITY, ADDITION };

class ip_address
{
    uint32_t address_;

public:
    void reset(uint32_t ip)
    {
        address_ = utils::htonl(ip);
    }

    ip_address(const ip_address &ip) : address_(ip.address_) {}

    explicit ip_address(uint32_t ip) : address_(utils::htonl(ip)) {}

    void to_string(string &) const;

    ip_address() : ip_address(0) {}


    bool operator==(uint32_t cmp) const
    {
        return address_ == utils::htonl(cmp);
    }

    bool operator==(const ip_address &cmp) const
    {
        return address_ == cmp.address_;
    }

    uint32_t get_address() const
    {
        return utils::ntohl(address_);
    }

    const uint8_t *get_value_address() const
    {
        return reinterpret_cast<const uint8_t *>(&address_);
    }
};

class hash_node;

class dns_value
{
    struct __attribute__((packed)) __raw {
        //NOTE: all data are stored as NET order.
        uint16_t name;
        uint16_t type;
        uint16_t clazz;
        // here should no padding
        uint32_t ttl;
        uint16_t length;
    };

    static_assert(sizeof(__raw) == (12), "dns_value size error, should be 12B");

    __raw raw;

    uint16_t length;

    uint8_t *data;

    void simple_copy(const dns_value &v)
    {
        raw.name = v.raw.name;
        raw.type = v.raw.type;
        raw.clazz = v.raw.clazz;
        raw.ttl = v.raw.ttl;
        raw.length = v.raw.length;

        length = utils::ntohs(raw.length);
    }

public:
    static uint8_t *from_data(uint8_t *begin, uint8_t *end, dns_value &);

    size_t get_rdata_size()
    {
        return 12 + length;
    }

    dns_value(uint16_t name, uint16_t type, uint16_t clazz, uint32_t t, uint16_t length, uint8_t *v)
    {
        raw.name = name;
        raw.type = type;
        raw.clazz = clazz;
        raw.ttl = t;
        raw.length = length;

        length = utils::ntohs(raw.length);

        this->data = new uint8_t[length];
        memmove(this->data, v, length);
    }

    dns_value(dns_value &&v)
    {
        *this = std::move(v);
    }

    void operator=(dns_value &&v)
    {
        simple_copy(v);
        data = v.data;
        v.data = nullptr;
        length = v.length;
    }

    void operator=(const dns_value &v)
    {
        simple_copy(v);
        auto l = utils::ntohs(raw.length);
        this->data = new uint8_t[l];
        memmove(this->data, v.data, l);

        length = v.length;
    }

    dns_value()
    {
        memset(this, 0, sizeof(dns_value));
    }

    ~dns_value()
    {
        delete[] data;
    }

    uint8_t *to_data(uint8_t *) const;

    uint16_t get_type() const
    {
        return raw.type;
    }

    uint16_t get_ttl() const
    {
        return raw.ttl;
    }

    uint8_t *get_data() const
    {
        return data;
    }
};

class record_node
{
    friend class hash_node;
    friend class dns_package_builder;
    friend class hash::hashtable;

    domain_name name;

    uint16_t answer_count;
    uint16_t authority_count;

    dns_value *answer;
    dns_value *authority;

public:
    void set_answers(std::vector<dns_value> &);
    void set_authority_answers(std::vector<dns_value> &);

    uint32_t get_answer_count() const
    {
        return answer_count;
    }

    uint16_t get_authority_count() const
    {
        return authority_count;
    }

    void to_data(uint8_t *) const;

    uint32_t get_data_length() const;

    record_node()
    {
        memset(this, 0, sizeof(*this));
    }

    explicit record_node(domain_name);

    ~record_node();

    domain_name get_name() const
    {
        return name;
    }

    bool operator==(const record_node &) const;

    bool operator==(domain_name) const;

    void to_string(string &);

    ip_address *get_record_A() const;

    void swap_A();
};

class hash_node
{
    friend class hash::hashtable;

    record_node *value;
    hash_node *lru_next;
    hash_node *lru_prev;

    hash_node(record_node *p) : value(p)
    {
        lru_next = lru_prev = nullptr;
    }

    ~hash_node()
    {
        delete value;
    }

    record_node *operator->()
    {
        return value;
    }

    operator record_node *()
    {
        return value;
    }

    record_node *get_node()
    {
        return value;
    }

    void swap_A()
    {
        value->swap_A();
    }
};

namespace fmt
{
    template <>
    struct formatter<record_node> {
        template <typename PC>
        constexpr auto parse(PC &ctx)
        {
            return ctx.begin();
        }

        template <typename FC>
        auto format(const record_node &, FC &ctx)
        {
            return format_to(ctx.begin(), "node");
        }
    };

    template <>
    struct formatter<ip_address> {
        template <class PC>
        constexpr auto parse(PC &ctx)
        {
            return ctx.begin();
        }

        template <class T>
        auto format(const ip_address &ip, T &ctx)
        {
            string str;
            ip.to_string(str);
            return format_to(ctx.begin(), "{0}", str);
        }
    };
}  // namespace fmt

#endif
