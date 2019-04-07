/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// dns.cpp: DNS parser implements

#include "dns.h"
#include "utils.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <exception>
#include <utility>

namespace
{
    uint16_t getTwoByte(uint8_t* _ptr)
    {
        uint16_t ret = *_ptr;
        ret = static_cast<uint16_t>(ret << 8);
        ret += *(_ptr + 1);
        return ret;
    }

}  // namespace

namespace dns
{
    using namespace dns_values;
    using namespace dns_utils;

    namespace dns_utils
    {
        bool ip_string_to_uint32(const char* ip, uint32_t& ret)
        {
            return utils::check_ip_address(ip, ret);
        }

        const char* query_string_parser(uint8_t* begin,
                                        uint8_t* buffer,
                                        uint8_t* buffer_end,
                                        uint32_t& length)
        {
            length = 0;
            auto ptr = begin;
            do {
                if (unlikely(ptr > buffer_end)) {
                    return nullptr;
                }
                if (unlikely(*ptr >= 0x80)) {
                    return nullptr;
                }
                if (unlikely((*ptr >> 4) == 0xc)) {
                    assert(buffer != nullptr);
                    ptr = buffer + ((*ptr & 0x3f) + *(ptr + 1));
                }
                length = length + *ptr + 1;
                ptr = ptr + *ptr + 1;
            } while (*ptr != 0x00);

            char* ret = new char[length + 1];
            char* pointer = ret;
            ptr = begin;
            do {
                if (unlikely((*ptr >> 4) == 0xc)) {
                    assert(buffer != nullptr);
                    ptr = buffer + ((*ptr & 0x3f) + *(ptr + 1));
                }
                auto count = *ptr;
                ptr++;
                while (count > 0) {
                    if (unlikely(!isalnum(*ptr))) {
                        delete[] ret;
                        return nullptr;
                    }
                    *pointer = tolower(*ptr);
                    pointer++;
                    ptr++;
                    count--;
                }
                *pointer = '.';
                pointer++;
            } while (*ptr != 0x00);
            *(pointer - 1) = 0;
            return ret;
        }

        const char* query_string_parser(uint8_t* begin, uint8_t* buffer)
        {
            int length = 0;
            auto ptr = begin;
            do {
                if (unlikely((*ptr >> 4) == 0xc)) {
                    assert(buffer != nullptr);
                    ptr = buffer + ((*ptr & 0x3f) + *(ptr + 1));
                }
                length = length + *ptr + 1;
                ptr = ptr + *ptr + 1;
            } while (*ptr != 0x00);
            char* ret = new char[length + 1];
            char* pointer = ret;
            ptr = begin;
            do {
                if (unlikely((*ptr >> 4) == 0xc)) {
                    assert(buffer != nullptr);
                    ptr = buffer + ((*ptr & 0x3f) + *(ptr + 1));
                }
                auto count = *ptr;
                ptr++;
                while (count > 0) {
                    *pointer = *ptr;
                    pointer++;
                    ptr++;
                    count--;
                }
                *pointer = '.';
                pointer++;
            } while (*ptr != 0x00);
            *(pointer - 1) = 0;
            return ret;
        }

        int query_string_generator(const char* name, uint8_t* buffer, size_t buffer_size)
        {
            auto length = strlen(name);
            if (unlikely(buffer_size < length + 2)) {
                return -1;
            }
            uint8_t* begin = buffer;
            memmove(begin + 1, name, strlen(name) + 1);
            while (true) {
                uint8_t next_count = 0;
                uint8_t* p = begin + 1;

                for (; *p != 0x0 && *p != '.'; p++) {
                    next_count++;
                }
                *begin = next_count;
                if (*p == 0x0) {
                    break;
                }
                begin = p;
            }
            return length + 2;
        }

    }  // namespace dns_utils

    dns_packet* dns_packet::fromDataBuffer(const uv_buf_t* buf, dns_parse_status& status)
    {
        status = dns_parse_status::format_error;
        uint8_t* start = reinterpret_cast<uint8_t*>(buf->base);
        uint8_t* end = reinterpret_cast<uint8_t*>(buf->base + buf->len);
        if (unlikely(buf->len <= 12)) {
            status = dns_parse_status::format_error;
            return nullptr;
        }
        dns_packet pack;
        pack.data = new uint8_t[buf->len];
        memmove(pack.data, start, buf->len);
        pack.flag = pack.getFlag();
        pack.flag_pointer = pack.data + 2;
        pack.id = pack.getQueryID();
        const int DNS_FLAG_Z = 9;
        if (flag_is_set(pack.flag_pointer, DNS_FLAG_Z)) {
            status = dns_parse_status::format_error;
            return nullptr;
        }
        bool is_response = pack.isResponse();
        auto oc = pack.getOPCode();
        if (unlikely(oc >= DNS_OPCODE_SERVER_STATUS)) {
            status = dns_parse_status::format_error;
            return nullptr;
        }
        auto qcount = pack.getQuestionCount();
        if (unlikely(qcount != 1)) {
            status = dns_parse_status::number_error;
            return nullptr;
        }
        auto acount = pack.getAnswerRRCount();
        if (likely(!is_response)) {
            auto authorcount = pack.getAuthorityRRCount();
            if (unlikely(acount > 0 || authorcount > 0)) {
                status = dns_parse_status::number_error;
                return nullptr;
            }
            auto rc = pack.getReturnCode();
            if (unlikely(rc != DNS_RCODE_NOERROR)) {
                status = dns_parse_status::format_error;
                return nullptr;
            }
        }
        uint32_t length;
        auto name = query_string_parser(
            start + DNS_FORMAT_HEADER_LENGTH, start + DNS_FORMAT_HEADER_LENGTH, end, length);
        if (unlikely((start + length + 4) > end)) {
            return nullptr;
        }
        uint16_t* type_pointer =
            reinterpret_cast<uint16_t*>(start + length + DNS_FORMAT_HEADER_LENGTH + 1);
        auto type = utils::htons(*type_pointer);
        auto clazz = utils::htons(*(type_pointer + 1));
        if (type > DNS_TYPE_TXT) {
            delete[] name;
            return nullptr;
        }
        if (unlikely(clazz != DNS_CLASS_IN)) {
            delete[] name;
            return nullptr;
        }
        auto ret = new dns_packet;
        ret->swap(std::move(pack));
        query q(name, type, clazz);
        std::swap(ret->this_query, q);
        if (is_response) {
            status = dns_parse_status::response_ok;
        } else {
            status = dns_parse_status::request_ok;
        }
        pack.parsed = true;
        return ret;
    }

    dns_packet* dns_packet::fromDataBuffer(uv_buf_t* buf)
    {
        return fromDataBuffer(reinterpret_cast<uint8_t*>(buf->base), buf->len);
    }

    dns_packet* dns_packet::fromDataBuffer(uint8_t* _data, uint32_t _size)
    {
        auto buf = new uint8_t[_size];
        memmove(buf, _data, _size);
        const auto ret = new dns_packet;
        ret->data = buf;
        ret->size = _size;
        return ret;
    }

    dns_packet::~dns_packet()
    {
        if (unlikely(data != nullptr)) {
            delete[] data;
        }
    }

    uint16_t dns_packet::getQueryID() const
    {
        return *reinterpret_cast<uint16_t*>(data);
    }

    uint16_t dns_packet::getFlag() const
    {
        return getTwoByte(data + 2);
    }

    void dns_packet::parse()
    {
        parsed = true;
        this->id = getQueryID();
        this->flag = getFlag();
        flag_pointer = data + 2;
        auto q = query(data + 12);
        std::swap(this->this_query, q);
    }

    bool dns_packet::isQuery() const
    {
        test_flag();
        return !flag_is_set(flag_pointer, dns_values::DNS_FLAGS_BIT_QUERY);
    }

    bool dns_packet::isResponse() const
    {
        return !isQuery();
    }

    uint8_t dns_packet::getOPCode() const
    {
        test_flag();
        return (flag >> 11) & 0x0f;
    }

    bool dns_packet::isAA() const
    {
        test_flag();
        return isResponse() && flag_is_set(flag_pointer, DNS_FLAGS_RESP_AA);
    }

    bool dns_packet::isTC() const
    {
        test_flag();
        return flag_is_set(flag_pointer, DNS_FLAGS_BIT_TC);
    }

    bool dns_packet::isRD() const
    {
        test_flag();
        return flag_is_set(flag_pointer, DNS_FLAGS_BIT_RD);
    }

    bool dns_packet::isRA() const
    {
        test_flag();
        return isResponse() && flag_is_set(flag_pointer, DNS_FLAGS_RESP_RA);
    }

    bool dns_packet::isAD() const
    {
        test_flag();
        return flag_is_set(flag_pointer, DNS_FLAGS_RESP_ANSWER_AUTHENTICATED);
    }


    uint8_t dns_packet::getReturnCode() const
    {
        return flag & 0xf;
    }

    uint16_t dns_packet::getQuestionCount() const
    {
        return getTwoByte(data + 4);
    }

    uint16_t dns_packet::getAnswerRRCount() const
    {
        return getTwoByte(data + 6);
    }

    uint16_t dns_packet::getAuthorityRRCount() const
    {
        return getTwoByte(data + 8);
    }

    uint16_t dns_packet::getAdditionalRRCount() const
    {
        return getTwoByte(data + 10);
    }

    dns_packet* dns_packet::build_response_with_records(dns_packet* incoming, record_node* record)
    {
        dns_package_builder builder;
        builder.as_response().set_id(incoming->getQueryID());
        if (incoming->isRD()) {
            builder.set_RD();
            builder.set_resp_RA();
        }
        builder.set_query(incoming->getQuery()).add_record(record);
        return builder.build();
    }

    namespace
    {
        uint8_t* generate_nodes(uint8_t* begin,
                                uint8_t* end,
                                int& count,
                                std::vector<dns_value>& out)
        {
            int c = 0;
            for (; begin < end;) {
                dns_value v;
                begin = dns_value::from_data(begin, end, v);
                out.emplace_back(std::move(v));
                c++;

                if (c == count) {
                    break;
                }

                if (begin != nullptr) {
                } else {
                    break;
                }
            }
            count = c;
            return begin;
        }
    }  // namespace

    record_node* dns_packet::generate_record_node()
    {
        uint8_t* pointer = data;
        record_node* node = nullptr;
        if (!parsed) {
            parse();
        }
        pointer = pointer + 12 + strlen(this_query.getName()) + 6;
        //pointer should be first byte of Answer section
        //Note: 12 = DNS header length, 6 = 2 + 2 + 2 => query_name + DNS_TYPE + DNS_CLASS

        if ((getAuthorityRRCount() + getAnswerRRCount()) == 0) {
            return nullptr;
        }
        uint8_t* end = data + size;

        uint8_t* begin = pointer;

        std::vector<dns_value> values;

        int c = getAnswerRRCount();

        begin = generate_nodes(begin, end, c, values);

        if (c != getAnswerRRCount()) {
            return nullptr;
        }

        node = new record_node(this_query.getName());

        node->set_answers(values);

        if (begin != nullptr) {
            values.clear();

            c = getAuthorityRRCount();

            begin = generate_nodes(begin, end, c, values);

            if (c != getAuthorityRRCount()) {
                delete node;
                return nullptr;
            }

            node->set_authority_answers(values);
        }

        return node;
    }

    void dns_packet::swap(dns_packet&& pack)
    {
        std::swap(pack.data, data);
        std::swap(pack.size, size);
        std::swap(pack.flag_pointer, flag_pointer);
        std::swap(pack.id, id);
        std::swap(pack.flag, flag);
        std::swap(pack.this_query, this_query);
        std::swap(pack.parsed, parsed);
    }

    int query::query_section_builder(
        domain_name dname, uint8_t* buf, size_t buf_size, uint16_t type, uint16_t clazz)
    {
        auto ret = query_string_generator(dname, buf, buf_size);
        if (unlikely(ret == -1)) {
            return -1;
        }
        auto pointer = reinterpret_cast<uint16_t*>(buf + ret);
        pointer[0] = utils::htons(type);
        pointer[1] = utils::htons(clazz);

        return ret + 4;
    }

    int query::query_section_builder(const query& query, uint8_t* buf, size_t buf_size)
    {
        return query_section_builder(query.name, buf, buf_size, query.type, query.clazz);
    }


    query::query(uint8_t* _from)
    {
        name = query_string_parser(_from);
        auto name_length = strlen(name);

        type = getTwoByte(_from + name_length + 2);
        clazz = getTwoByte(_from + name_length + 4);
    }

    query::~query()
    {
        if (unlikely((name != nullptr))) {
            delete[] name;
        }
    }

    const uint8_t query::QUERY_CLASS_IN = 1;
    const uint8_t query::QUERY_TYPE_A = 1;

    // dns_package_builder

    dns_package_builder::dns_package_builder()
    {
        rdata = query_pointer = nullptr;
        rdata_length = query_length = 0;
        flag_pointer = header + 2;
        memset(header, 0, sizeof(header));
        answer_count = auth_count = 0;
    }

    dns_package_builder::~dns_package_builder()
    {
        delete[] query_pointer;
        delete[] rdata;
    }

    reference dns_package_builder::set_id(uint16_t id)
    {
        uint16_t* p = reinterpret_cast<uint16_t*>(header);
        *p = id;
        return *this;
    }

    reference dns_package_builder::as_response()
    {
        flag_set(flag_pointer, DNS_FLAGS_BIT_QUERY, true);
        return *this;
    }

    reference dns_package_builder::as_query()
    {
        flag_set(flag_pointer, DNS_FLAGS_BIT_QUERY, false);
        return *this;
    }

    reference dns_package_builder::set_opcode(uint8_t code)
    {
        assert(code < 3);
        *flag_pointer = *flag_pointer | (code << 3);
        return *this;
    }

    reference dns_package_builder::set_TC()
    {
        flag_set(flag_pointer, DNS_FLAGS_BIT_TC, false);
        return *this;
    }

    reference dns_package_builder::set_resp_AA()
    {
        flag_set(flag_pointer, DNS_FLAGS_RESP_AA);
        return *this;
    }

    reference dns_package_builder::set_RD()
    {
        flag_set(flag_pointer, DNS_FLAGS_BIT_RD);
        return *this;
    }

    reference dns_package_builder::set_resp_RA()
    {
        flag_set(flag_pointer, DNS_FLAGS_RESP_RA);
        return *this;
    }

    reference dns_package_builder::set_resp_AnswerAuthenicated()
    {
        flag_set(flag_pointer, DNS_FLAGS_RESP_ANSWER_AUTHENTICATED);
        return *this;
    }

    reference dns_package_builder::set_reply_code(uint8_t rc)
    {
        assert(rc <= DNS_RCODE_NOTZONE);
        auto ptr = flag_pointer + 1;
        *ptr = (*ptr & 0xf0) | rc;
        return *this;
    }

    reference dns_package_builder::set_query(const char* name)
    {
        const static size_t buffer_size = 256;
        const static int query_count_offset = 5;
        static uint8_t buffer[buffer_size];
        query_length = query::query_section_builder(
            name, buffer, buffer_size, dns::dns_values::DNS_TYPE_A, dns::dns_values::DNS_CLASS_IN);

        assert(header[query_count_offset] == 0);
        header[query_count_offset]++;
        query_pointer = new uint8_t[query_length];
        memcpy(query_pointer, buffer, query_length * sizeof(uint8_t));
        return *this;
    }


    reference dns_package_builder::set_query(const query& q)
    {
        const static size_t buffer_size = 256;
        const static int query_count_offset = 5;
        static uint8_t buffer[buffer_size];

        query_length = query::query_section_builder(q, buffer, buffer_size);
        assert(header[query_count_offset] == 0);
        header[query_count_offset]++;

        query_pointer = new uint8_t[query_length];
        memmove(query_pointer, buffer, query_length * sizeof(uint8_t));
        return *this;
    }

    dns_packet* dns_package_builder::build()
    {
        const int answer_count_offset = 3;

        auto ret = new dns_packet;
        ret->size = 12 + query_length + rdata_length;

        auto data = ret->data = new uint8_t[ret->size];

        uint16_t* ap = reinterpret_cast<uint16_t*>(header);
        ap[answer_count_offset] = utils::htons(answer_count);

        memmove(data, header, 12);
        memmove(data + 12, query_pointer, query_length);
        if (rdata_length != 0) {
            memmove(data + 12 + query_length, rdata, rdata_length);
        }

        return ret;
    }

    reference dns_package_builder::add_record(record_node* r)
    {
        this->rdata_length = r->get_data_length();
        this->rdata = new uint8_t[rdata_length + 10];

        memset(this->rdata, 0xdf, rdata_length + 10);

        r->to_data(this->rdata);

        answer_count = r->get_answer_count();
        auth_count = r->get_authority_count();

        return *this;
    }

    void dns_package_builder::basic_query_package(reference ref, const char* domain)
    {
        ref.as_query().set_opcode(DNS_OPCODE_STAND_QUERY).set_RD().set_resp_RA();
        ref.set_query(domain).set_id(utils::rand_value());
    }

}  // namespace dns


// class ip_address
void ip_address::to_string(string& buffer) const
{
    if (buffer.capacity() < 20) {
        buffer.reserve(20);
    }
    uint32_t actual = utils::ntohl(address_);

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
    uint16_t host_length = utils::ntohs(length);
    uint8_t* value = new uint8_t[host_length];

    memmove(value, pv, host_length);

    v.raw.name = name;
    v.raw.type = type;
    v.raw.clazz = clazz;
    v.raw.ttl = ttl;
    v.raw.length = length;

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
    const auto raw_size = sizeof(raw);
    const auto len = utils::ntohs(raw.length);

    memmove(p, &raw, raw_size);
    memmove(p + raw_size, data, len);
    return p + raw_size + len;
}

// class record node

ip_address* record_node::get_record_A() const
{
    for (int i = 0; i < answer_count; i++) {
        auto& v = answer[i];
        if (v.get_type() == utils::ntohs(dns::DNS_TYPE_A)) {
            uint8_t* pdata = v.get_data();
            uint32_t ip = utils::ntohl(*reinterpret_cast<uint32_t*>(pdata));
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
    delete[] answer;
    delete[] authority;
}

void record_node::set_authority_answers(std::vector<dns_value>& an)
{
    this->authority_count = an.size();
    this->authority = new dns_value[an.size()];

    for (size_t i = 0; i < an.size(); i++) {
        authority[i] = std::move(an[i]);
    }
}

void record_node::set_answers(std::vector<dns_value>& an)
{
    this->answer_count = an.size();
    this->answer = new dns_value[an.size()];

    for (int i = 0; i < answer_count; i++) {
        answer[i] = std::move(an[i]);
    }
}

void record_node::swap_A()
{
    //TODO fix me
    int firstA = 0;
    for (; firstA < answer_count; firstA++) {
        if (answer[firstA].get_type() == utils::ntohs(dns::DNS_TYPE_A)) {
            break;
        }
    }
    if (firstA >= answer_count - 1) {
        // no A stored or only single A stored.
        return;
    }

    dns_value last(std::move(answer[answer_count - 1]));
    memmove(answer + firstA + 1, answer + firstA, sizeof(dns_value) * (answer_count - firstA - 1));
    answer[firstA] = std::move(last);
}

bool record_node::operator==(domain_name dn) const
{
    return utils::str_equal(dn, name);
}
