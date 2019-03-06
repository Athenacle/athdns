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

#include <arpa/inet.h>
#include "athdns.h"

using domain_name = const char *;

enum class reply_type { NONE, ANSWER, AUTHORITY, ADDITION };

class ip_address
{
    uint32_t address_;

public:
    void reset(uint32_t ip)
    {
        address_ = htonl(ip);
    }

    ip_address(const ip_address &ip) : address_(ip.address_) {}

    explicit ip_address(uint32_t ip) : address_(htonl(ip)) {}

    void to_string(string &) const;

    ip_address() : ip_address(0) {}


    bool operator==(uint32_t cmp) const
    {
        return address_ == htonl(cmp);
    }

    bool operator==(const ip_address &cmp) const
    {
        return address_ == cmp.address_;
    }

    uint32_t get_address() const
    {
        return ntohl(address_);
    }

    const uint8_t *get_value_address() const
    {
        return reinterpret_cast<const uint8_t *>(&address_);
    }
};

class record_node
{
    friend class dns_package_builder;
    friend class hash::hashtable;

    domain_name name;

    record_node *lru_next;
    record_node *lru_prev;

    uint32_t record_ttl;

    reply_type type;

    uint16_t offset;

    void fill_data(uint8_t *) const;

protected:
    record_node *node_next;

    uint16_t record_type;
    uint16_t record_class;
    uint16_t record_data_length;

    bool domain_name_equal(domain_name) const;

    void set_type(uint16_t t)
    {
        record_type = t;
    }

    void set_class(uint16_t c)
    {
        record_class = c;
    }

    void set_data_length(uint16_t dl)
    {
        record_data_length = dl;
    }

    virtual void set_value();

    record_node(uint8_t *, uint8_t *, domain_name);

    void shared_data_fill_offset(uint8_t *, uint16_t) const;

    virtual const uint8_t *get_value() const = 0;

public:
    record_node();
    explicit record_node(domain_name);

    virtual ~record_node();

    domain_name get_name() const
    {
        return name;
    }

    bool operator==(const record_node &) const;

    bool operator==(domain_name) const;

    void *operator new(size_t);

    void operator delete(void *);

    void get_value(uint32_t &, uint16_t &, uint16_t &, uint16_t &) const;

    void set_ttl(uint32_t ttl)
    {
        record_ttl = ttl;
    }

    void set_tail(record_node *);

    int next_count() const;

    record_node *get_next() const
    {
        return node_next;
    }

    virtual void to_string(string &) const = 0;

    int to_data(
        uint8_t *buffer, size_t buf_size, int, uint16_t &rr_count, uint16_t &ra_count) const;

    ip_address *get_record_A() const;
};

class record_node_A : public record_node
{
    ip_address address;

    virtual void set_value() override;

protected:
    virtual const uint8_t *get_value() const override;

public:
    record_node_A();
    record_node_A(uint8_t *, uint8_t *, domain_name);

    record_node_A(domain_name, ip_address &);
    record_node_A(domain_name, uint32_t);

    virtual ~record_node_A();

    bool operator==(const record_node_A &) const;
    bool operator==(const ip_address &) const;

    virtual void to_string(string &) const override;
};

class record_node_CNAME : public record_node
{
    domain_name actual_name;
    uint8_t *value;

protected:
    virtual const uint8_t *get_value() const override;

public:
    record_node_CNAME(uint8_t *, uint8_t *, domain_name);
    virtual ~record_node_CNAME();

    virtual void to_string(string &) const override;
    domain_name get_actual_name() const;
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
        auto format(const record_node &p, FC &ctx)
        {
            string str;
            p.to_string(str);
            return format_to(ctx.begin(), "{0}->{0}", p.get_name(), str);
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
