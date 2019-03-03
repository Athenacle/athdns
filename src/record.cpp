
#include "record.h"
#include "dns.h"
#include "utils.h"

#include <arpa/inet.h>
#include <cassert>
#include <cstring>

using namespace dns::dns_values;

// class ip_address
void ip_address::to_string(string &buffer) const
{
    if (buffer.capacity() < 20) {
        buffer.reserve(20);
    }
    uint32_t actual = ntohl(address_);

    char buf[8];
    for (int i = 0; i < 4; i++) {
        uint8_t part = (actual >> ((3 - i) * 8)) & 0xff;
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
    auto next = node_next;
    if (unlikely(name != nullptr)) {
        utils::strfree(name);
    }
    if (unlikely(next != nullptr)) {
        delete next;
    }
}

record_node::record_node(uint8_t *buffer, uint8_t *begin, const char *domain)
{
    lru_next = lru_prev = node_next = nullptr;

    uint16_t *p = reinterpret_cast<uint16_t *>(begin);

    offset = ntohs(*p) & 0x3fff;

    record_type = ntohs(*(p + 1));
    record_class = ntohs(*(p + 2));
    record_ttl = ntohl(*(reinterpret_cast<uint32_t *>(begin + 6)));
    record_data_length = ntohs(*(p + 5));

    if (domain != nullptr) {
        name = utils::strdup(domain);
    } else {
        name = dns::dns_utils::query_string_parser(buffer + offset, buffer);
    }
}

void record_node::fill_data(uint8_t *buf) const
{
    const int type_offset_16 = 1;
    const int class_offset_16 = 2;
    const int dl_offset_16 = 5;
    const int ttl_offset_32 = 1;

    uint16_t *value_pointer = reinterpret_cast<uint16_t *>(buf);

    if (likely(offset < 256)) {
        buf[0] = 0xc0;
        buf[1] = offset;
    } else {
        buf[0] = ((offset & 0xff00) >> 8) | 0xc;
        buf[1] = offset & 0xff;
    }

    value_pointer[type_offset_16] = htons(record_type);
    value_pointer[class_offset_16] = htons(record_class);
    value_pointer[dl_offset_16] = htons(record_data_length);

    reinterpret_cast<uint32_t *>(buf + 2)[ttl_offset_32] = htonl(record_ttl);

    //  begin     | domain name + type + class + ttl + data length | value
    //  buffer    + 2           + 2    + 2     +  4  + 2           |
    //                                                    pointer -> ^
    uint8_t *pointer = buf + 2 + 2 + 2 + 4 + 2;
    memcpy(pointer, get_value(), record_data_length);
}

int record_node::next_count() const
{
    auto begin = this;
    auto ret = 1;
    while (begin->node_next != nullptr) {
        ret++;
        begin = begin->node_next;
    }
    return ret;
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
    offset = DNS_FORMAT_HEADER_LENGTH;
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

void record_node::set_tail(record_node *tail)
{
    auto begin = this;
    while (begin->node_next != nullptr) {
        begin = begin->node_next;
    }
    assert(begin->node_next == nullptr);
    begin->node_next = tail;
}


void record_node::shared_data_fill_offset(uint8_t *pointer, uint16_t value) const
{
    uint8_t high = value >> 8;
    uint8_t low = value & 0xff;
    high = high | 0xc0;
    pointer[0] = high;
    pointer[1] = low;
}

int record_node::to_data(
    uint8_t *buffer, size_t buf_size, int, uint16_t &aa_count, uint16_t &) const
{
    size_t remain_size = buf_size;
    const record_node *pointer = this;
    uint8_t *buf_pointer = buffer;
    size_t used_size = 0;
    while (pointer != nullptr) {
        size_t pointer_node_size = 12 + pointer->record_data_length;
        if (unlikely(buf_size < pointer_node_size)) {
            return -1;
        }
        aa_count++;
        pointer->fill_data(buf_pointer);
        used_size += pointer_node_size;
        buf_pointer = buffer + used_size;
        remain_size -= used_size;
        pointer = pointer->node_next;
    }
    return used_size;
}


// class record_node_A

record_node_A::~record_node_A() {}


record_node_A::record_node_A(domain_name name, uint32_t ip) : record_node(name), address(ip)
{
    set_value();
}

record_node_A::record_node_A(uint8_t *buffer, uint8_t *begin, domain_name name)
    : record_node(buffer, begin, name)
{
    uint8_t *pointer = begin + 12;
    uint32_t ip = 0;
    ip = pointer[0] << 24 | pointer[1] << 16 | pointer[2] << 8 | pointer[3];
    address.reset(ip);
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

const uint8_t *record_node_A::get_value() const
{
    return address.get_value_address();
}

// record_node_CNAME

record_node_CNAME::~record_node_CNAME()
{
    utils::strfree(actual_name);
    utils::strfree(value);
}

record_node_CNAME::record_node_CNAME(uint8_t *buffer, uint8_t *begin, domain_name name)
    : record_node(buffer, begin, name)
{
    uint8_t *pointer = begin + DNS_FORMAT_ANSWER_VALUE_OFFSET;
    actual_name = dns::dns_utils::query_string_parser(pointer, buffer);
    value = utils::str_allocate<uint8_t>(record_data_length);
    memcpy(value, pointer, record_data_length);
}

void record_node_CNAME::to_string(string &str) const
{
    str = "CNAME ->";
    str.append(actual_name);
}

domain_name record_node_CNAME::get_actual_name() const
{
    return actual_name;
}

const uint8_t *record_node_CNAME::get_value() const
{
    return value;
}
