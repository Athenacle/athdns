/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// record.cpp: record implements

#include "record.h"
#include "dns.h"
#include "utils.h"

#include <arpa/inet.h>
#include <cassert>
#include <cstring>

using namespace dns::dns_values;

// class ip_address
void ip_address::to_string(string& buffer) const
{
    if (buffer.capacity() < 20) {
        buffer.reserve(20);
    }
    uint32_t actual = ntohl(address_);

    char buf[8];
    for (int i = 0; i < 4; i++) {
        uint8_t part = (actual >> ((3 - i) * 8)) & 0xff;
        snprintf(buf, 8, "%d.", part);
        buffer.append(buf);
    }
    buffer.erase(buffer.length() - 1);
}

uint8_t* dns_value::from_data(uint8_t* begin, uint8_t* end, dns_value& v)
{
    uint16_t* p16 = reinterpret_cast<uint16_t*>(begin);
    uint32_t* p32 = reinterpret_cast<uint32_t*>(begin + 6);
    uint8_t* pv = begin + 12;

    uint16_t name = (p16[0]);
    uint16_t type = (p16[1]);
    uint16_t clazz = (p16[2]);
    uint32_t ttl = (*p32);
    uint16_t length = (p16[5]);
    uint16_t host_length = ntohs(length);
    uint8_t* value = new uint8_t[host_length];

    memmove(value, pv, host_length);

    v.name = name;
    v.type = type;
    v.clazz = clazz;
    v.ttl = ttl;
    v.length = length;
    v.data = value;

    begin = begin + 12 + host_length;

    if (begin > end) {
        return nullptr;
    } else {
        return begin;
    }
}

uint8_t* dns_value::to_data(uint8_t* p) const
{
    memmove(p, this, 12);
    memmove(p + 12, data, ntohs(length));
    return p + 12 + ntohs(length);
}

// class record node

ip_address* record_node::get_record_A() const
{
    for (int i = 0; i < answer_count; i++) {
        auto& v = answer[i];
        if (v.get_type() == ntohs(DNS_TYPE_A)) {
            uint8_t* pdata = v.get_data();
            uint32_t ip = ntohl(*reinterpret_cast<uint32_t*>(pdata));
            return new ip_address(ip);
        }
    }
    return nullptr;
}

void record_node::to_string(string& str)
{
    str = name;
}

uint32_t record_node::get_data_length() const
{
    uint32_t ret = 0;
    for (int i = 0; i < answer_count; i++) {
        ret += answer[i].get_rdata_size();
    }

    for (int i = 0; i < authority_count; i++) {
        ret += authority[i].get_rdata_size();
    }
    return ret;
}

void record_node::to_data(uint8_t* pointer) const
{
    uint8_t* p = pointer;
    for (int i = 0; i < answer_count; i++) {
        p = answer[i].to_data(p);
    }

    for (int i = 0; i < authority_count; i++) {
        p = authority[i].to_data(p);
    }

#ifndef NDEBUG
    auto end = pointer + get_data_length();
    assert(end == p);
#endif
}

record_node::record_node(domain_name n) : record_node()
{
    if (n != nullptr) {
        name = utils::str_dump(n);
    }
}

record_node::~record_node()
{
    if (name != nullptr) {
        delete[] name;
    }
    for (int i = 0; i < answer_count; i++) {
        (answer + i)->~dns_value();
    }
    free(answer);

    for (int i = 0; i < authority_count; i++) {
        (authority + i)->~dns_value();
    }
    free(authority);
}

void record_node::set_authority_answers(std::vector<dns_value>& an)
{
    this->authority_count = an.size();
    this->authority =
        reinterpret_cast<dns_value*>(malloc(this->authority_count * sizeof(dns_value)));

    for (size_t i = 0; i < an.size(); i++) {
        auto pa = authority + i;
        new (pa) dns_value(std::move(an[i]));
    }
}

void record_node::set_answers(std::vector<dns_value>& an)
{
    this->answer_count = an.size();
    this->answer = reinterpret_cast<dns_value*>(malloc(this->answer_count * sizeof(dns_value)));

    for (int i = 0; i < answer_count; i++) {
        auto pa = answer + i;
        new (pa) dns_value(std::move(an[i]));
    }
}

void record_node::swap_A()
{
    //TODO fix me
}

bool record_node::operator==(domain_name dn) const
{
    return utils::str_equal(dn, name);
}
