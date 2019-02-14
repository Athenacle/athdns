
#pragma once

#ifndef RECORD_H
#define RECORD_H

#include "dnsserver.h"

using domain_name = const char *;

class ip_address
{
    uint32_t address_;

public:
    ip_address(const ip_address &ip) : address_(ip.get_address()) {}

    explicit ip_address(uint32_t ip) : address_(ip) {}

    void to_string(string &) const;

    ip_address();

    bool operator==(uint32_t cmp) const
    {
        return address_ == cmp;
    }

    bool operator==(const ip_address &cmp) const
    {
        return address_ == cmp.get_address();
    }

    uint32_t get_address() const
    {
        return address_;
    }
};

class record_node
{
    friend class hash::hashtable;

    domain_name name;

    record_node *lru_next;
    record_node *lru_prev;

    uint32_t record_ttl;

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

    void get_value(uint32_t &, uint16_t &, uint16_t &, uint16_t &) const;

    void set_ttl(uint32_t ttl)
    {
        record_ttl = ttl;
    }

    virtual void to_string(string &) const = 0;

    virtual int to_data(uint8_t *, size_t, size_t, int &) const = 0;
};

class record_node_A : public record_node
{
    ip_address address;

    virtual void set_value() override;

public:
    record_node_A();
    record_node_A(domain_name, ip_address &);
    record_node_A(domain_name, uint32_t);

    bool operator==(const record_node_A &) const;
    bool operator==(const ip_address &) const;

    virtual void to_string(string &) const override;
    virtual int to_data(uint8_t *, size_t, size_t, int &) const override;
};

#endif
