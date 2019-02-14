
#include "record.h"
#include "dns.h"

#include <arpa/inet.h>
#include <cassert>

using namespace dns::dns_values;

// class ip_address
void ip_address::to_string(string &buffer) const
{
    if (buffer.capacity() < 20) {
        buffer.reserve(20);
    }
    char buf[8];
    for (int i = 0; i < 4; i++) {
        uint8_t part = (address_ >> ((3 - i) * 8)) & 0xff;
        sprintf(buf, "%d.", part);
        buffer.append(buf);
    }
    buffer.erase(buffer.length() - 1);
}


// class record node
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
    if (n != nullptr) {
        name = utils::strdup(n);
    }

    node_next = lru_prev = lru_next = nullptr;
    set_value();
}

void record_node::set_value()
{
    set_type(DNS_TYPE_A);
    set_ttl(256);
    set_data_length(0);
    set_class(DNS_CLASS_IN);
}


record_node::record_node() : record_node(nullptr) {}

void record_node::get_value(uint32_t &rttl,
                            uint16_t &rtype,
                            uint16_t &rclass,
                            uint16_t &rdata_len) const
{
    rttl = record_ttl;
    rtype = record_type;
    rclass = record_class;
    rdata_len = record_data_length;
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

// class record_node_A
record_node_A::record_node_A(domain_name name, uint32_t ip) : record_node(name), address(ip)
{
    set_value();
}

record_node_A::record_node_A(domain_name name,
                             ip_address &ip)  // : record_node(name), address(ip) {}
    : record_node_A(name, ip.get_address())
{
    set_value();
}

void record_node_A::set_value()
{
    set_type(DNS_TYPE_A);
    set_class(DNS_CLASS_IN);
    set_data_length(4);
    set_ttl(256);
}

bool record_node_A::operator==(const ip_address &ip) const
{
    return address == ip;
}

bool record_node_A::operator==(const record_node_A &a) const
{
    return domain_name_equal(a.get_name()) && this->operator==(a.address);
}

void record_node_A::to_string(string &str) const
{
    address.to_string(str);
}

int record_node_A::to_data(uint8_t *buffer,
                           size_t buffer_size,
                           size_t offset,
                           int &record_count) const
{
    if (buffer_size < 16)
        return -1;
    uint32_t ttl;
    uint16_t rtype, rclass, rdata_length;
    get_value(ttl, rtype, rclass, rdata_length);
    assert(offset < 0x3fff);

    uint16_t *p = reinterpret_cast<uint16_t *>(buffer);
    uint32_t *ttl_p = reinterpret_cast<uint32_t *>(buffer + 6);
    uint32_t *ip_p = reinterpret_cast<uint32_t *>(buffer + 12);

    if (offset <= 255) {
        buffer[0] = 0xc0;
        buffer[1] = offset;
    } else {
        buffer[0] = 0xc0 | (offset - 255);
        buffer[1] = offset & 0xff;
    }

    p[1] = htons(rtype);
    p[2] = htons(rclass);
    p[5] = htons(rdata_length);
    auto tttl = htonl(ttl);
    *ttl_p = tttl;
    *ip_p = address.get_address();
    record_count++;

    if (unlikely(node_next != nullptr)) {
        return 16 + node_next->to_data(buffer + 16, buffer_size - 16, offset, record_count);
    }
    return 16;
}
