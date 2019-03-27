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

    DnsPacket* DnsPacket::fromDataBuffer(const uv_buf_t* buf, dns_parse_status& status)
    {
        status = dns_parse_status::format_error;
        uint8_t* start = reinterpret_cast<uint8_t*>(buf->base);
        uint8_t* end = reinterpret_cast<uint8_t*>(buf->base + buf->len);
        if (unlikely(buf->len <= 12)) {
            status = dns_parse_status::format_error;
            return nullptr;
        }
        DnsPacket pack;
        pack._data = new uint8_t[buf->len];
        memmove(pack._data, start, buf->len);
        pack._flag = pack.getFlag();
        pack.flag_pointer = pack._data + 2;
        pack._id = pack.getQueryID();
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
        auto type = htons(*type_pointer);
        auto clazz = htons(*(type_pointer + 1));
        if (type > DNS_TYPE_TXT) {
            delete[] name;
            return nullptr;
        }
        if (unlikely(clazz != DNS_CLASS_IN)) {
            delete[] name;
            return nullptr;
        }
        Query q(name, type, clazz);
        std::swap(pack._query, (q));
        if (is_response) {
            status = dns_parse_status::response_ok;
        } else {
            status = dns_parse_status::request_ok;
        }
        pack.parsed = true;
        auto ret = new DnsPacket;
        ret->swap(std::move(pack));
        return ret;
    }

    DnsPacket* DnsPacket::fromDataBuffer(uv_buf_t* buf)
    {
        return fromDataBuffer(reinterpret_cast<uint8_t*>(buf->base), buf->len);
    }

    DnsPacket* DnsPacket::fromDataBuffer(uint8_t* _data, uint32_t _size)
    {
        auto buf = new uint8_t[_size];
        memmove(buf, _data, _size);
        const auto ret = new DnsPacket;
        ret->_data = buf;
        ret->_size = _size;
        return ret;
    }

    DnsPacket::~DnsPacket()
    {
        if (unlikely(_data != nullptr)) {
            delete[] _data;
        }
    }

    uint16_t DnsPacket::getQueryID() const
    {
        return *reinterpret_cast<uint16_t*>(_data);
    }

    uint16_t DnsPacket::getFlag() const
    {
        return getTwoByte(_data + 2);
    }

    void DnsPacket::parse()
    {
        parsed = true;
        this->_id = getQueryID();
        this->_flag = getFlag();
        flag_pointer = _data + 2;
        auto query = Query(_data + 12);
        std::swap(this->_query, query);
    }

    bool DnsPacket::isQuery() const
    {
        test_flag();
        return !flag_is_set(flag_pointer, dns_values::DNS_FLAGS_BIT_QUERY);
    }

    bool DnsPacket::isResponse() const
    {
        return !isQuery();
    }

    uint8_t DnsPacket::getOPCode() const
    {
        test_flag();
        return (_flag >> 11) & 0x0f;
    }

    bool DnsPacket::isAA() const
    {
        test_flag();
        return isResponse() && flag_is_set(flag_pointer, DNS_FLAGS_RESP_AA);
    }

    bool DnsPacket::isTC() const
    {
        test_flag();
        return flag_is_set(flag_pointer, DNS_FLAGS_BIT_TC);
    }

    bool DnsPacket::isRD() const
    {
        test_flag();
        return flag_is_set(flag_pointer, DNS_FLAGS_BIT_RD);
    }

    bool DnsPacket::isRA() const
    {
        test_flag();
        return isResponse() && flag_is_set(flag_pointer, DNS_FLAGS_RESP_RA);
    }

    bool DnsPacket::isAD() const
    {
        test_flag();
        return flag_is_set(flag_pointer, DNS_FLAGS_RESP_ANSWER_AUTHENTICATED);
    }


    uint8_t DnsPacket::getReturnCode() const
    {
        return _flag & 0xf;
    }

    uint16_t DnsPacket::getQuestionCount() const
    {
        return getTwoByte(_data + 4);
    }

    uint16_t DnsPacket::getAnswerRRCount() const
    {
        return getTwoByte(_data + 6);
    }

    uint16_t DnsPacket::getAuthorityRRCount() const
    {
        return getTwoByte(_data + 8);
    }

    uint16_t DnsPacket::getAdditionalRRCount() const
    {
        return getTwoByte(_data + 10);
    }

    DnsPacket* DnsPacket::build_response_with_records(DnsPacket* incoming, record_node* record)
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

    record_node* DnsPacket::generate_record_node()
    {
        uint8_t* pointer = _data;
        record_node* node = nullptr;
        if (!parsed) {
            parse();
        }
        pointer = pointer + 12 + strlen(_query.getName()) + 6;
        //pointer should be first byte of Answer section
        //Note: 12 = DNS header length, 6 = 2 + 2 + 2 => query_name + DNS_TYPE + DNS_CLASS

        if ((getAuthorityRRCount() + getAnswerRRCount()) == 0) {
            return nullptr;
        }
        uint8_t* end = _data + _size;
        int answer_count = 0;

        uint8_t* begin = pointer;
        while (true) {
            record_node* new_node;
            uint16_t* p = reinterpret_cast<uint16_t*>(begin);
            uint16_t offset = ntohs(*p) & 0x3fff;  // offset example: 0xc00c
            uint16_t type = ntohs(*(p + 1));
            uint16_t dlength = ntohs(*(p + 5));

            const char* name;

            //next_pointer: begin + length of ( offset(2) + type(2) + class (2) + ttl(4) + data length(2) + data length
            uint8_t* next_pointer = dlength + 2 + 2 + 2 + 4 + 2 + begin;

            if (offset == 0xc) {
                name = _query.getName();
            } else {
                name = nullptr;
            }
            answer_count++;
            switch (type) {
                case DNS_TYPE_A:
                    new_node = new record_node_A(_data, begin, name);
                    break;
                case DNS_TYPE_CNAME:
                    new_node = new record_node_CNAME(_data, begin, name);
                    break;
                default:
                    new_node = nullptr;
            }

            begin = next_pointer;
            if (node == nullptr) {
                node = new_node;
            } else {
                node->set_tail(new_node);
            }
            if (begin >= end || answer_count >= getAnswerRRCount() + getAuthorityRRCount()) {
                break;
            }
        }
        return node;
    }

    void DnsPacket::swap(DnsPacket&& pack)
    {
        std::swap(pack._data, _data);
        std::swap(pack._size, _size);
        std::swap(pack.flag_pointer, flag_pointer);
        std::swap(pack._id, _id);
        std::swap(pack._flag, _flag);
        std::swap(pack._query, _query);
        std::swap(pack.parsed, parsed);
    }

    int Query::query_section_builder(
        domain_name dname, uint8_t* buf, size_t buf_size, uint16_t type, uint16_t clazz)
    {
        auto ret = query_string_generator(dname, buf, buf_size);
        if (unlikely(ret == -1)) {
            return -1;
        }
        auto pointer = reinterpret_cast<uint16_t*>(buf + ret);
        pointer[0] = htons(type);
        pointer[1] = htons(clazz);

        return ret + 4;
    }

    int Query::query_section_builder(const Query& query, uint8_t* buf, size_t buf_size)
    {
        return query_section_builder(query._name, buf, buf_size, query._type, query._class);
    }


    Query::Query(uint8_t* _from)
    {
        _label_count = 0;
        _name = query_string_parser(_from);
        auto name_length = strlen(_name);

        _type = getTwoByte(_from + name_length + 2);
        _class = getTwoByte(_from + name_length + 4);
    }

    Query::~Query()
    {
        if (unlikely((_name != nullptr))) {
            delete[] _name;
        }
    }

    const uint8_t Query::QUERY_CLASS_IN = 1;
    const uint8_t Query::QUERY_TYPE_A = 1;

    // dns_package_builder

    dns_package_builder::dns_package_builder()
    {
        authority_pointer = answer_pointer = additional_pointer = query_pointer = nullptr;

        query_length = answer_length = addition_length = authority_length = 0;

        flag_pointer = header + 2;
        memset(header, 0, sizeof(header));
        answer_count = auth_count = 0;
    }

    dns_package_builder::~dns_package_builder()
    {
        delete[] query_pointer;
        delete[] authority_pointer;
        delete[] answer_pointer;
        delete[] additional_pointer;
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
        query_length = Query::query_section_builder(
            name, buffer, buffer_size, dns::dns_values::DNS_TYPE_A, dns::dns_values::DNS_CLASS_IN);

        assert(header[query_count_offset] == 0);
        header[query_count_offset]++;
        query_pointer = new uint8_t[query_length];
        memcpy(query_pointer, buffer, query_length * sizeof(uint8_t));
        return *this;
    }


    reference dns_package_builder::set_query(const Query& q)
    {
        const static size_t buffer_size = 256;
        const static int query_count_offset = 5;
        static uint8_t buffer[buffer_size];

        query_length = Query::query_section_builder(q, buffer, buffer_size);
        assert(header[query_count_offset] == 0);
        header[query_count_offset]++;

        query_pointer = new uint8_t[query_length];
        memmove(query_pointer, buffer, query_length * sizeof(uint8_t));
        return *this;
    }

    DnsPacket* dns_package_builder::build()
    {
        const int answer_count_offset = 3;

        auto ret = new DnsPacket;
        ret->_size = 12 + query_length + answer_length + authority_length + addition_length;
        auto data = ret->_data = new uint8_t[ret->_size];

        uint16_t* ap = reinterpret_cast<uint16_t*>(header);
        ap[answer_count_offset] = htons(answer_count);

        memmove(data, header, 12);
        memmove(data + 12, query_pointer, query_length);
        memmove(data + 12 + query_length, answer_pointer, answer_length);
        memmove(data + 12 + query_length + answer_length, authority_pointer, authority_length);
        memmove(data + 12 + query_length + answer_length + authority_length,
                additional_pointer,
                addition_length);

        return ret;
    }

    reference dns_package_builder::add_record(record_node* r)
    {
        const int buffer_size = 256;
        static uint8_t buffer[buffer_size];
        int count = 0;
        uint16_t offset = 0xc;

        answer_count = 0;
        auth_count = 0;

        answer_length = r->to_data(buffer, buffer_size, offset, answer_count, auth_count);
        answer_pointer = new uint8_t[answer_length];
        memmove(answer_pointer, buffer, answer_length * sizeof(uint8_t));
        uint16_t* answer_rr_pointer = reinterpret_cast<uint16_t*>(header) + 3;
        *answer_rr_pointer = htons(count);
        return *this;
    }

    reference dns_package_builder::set_answer_record(record_node* node)
    {
        const size_t size = 512;
        answer_pointer = new uint8_t[512];  // buffer_allocate(512);
        assert(query_length > 0);
        assert(node != nullptr);

        answer_count = auth_count = 0;

        answer_length = node->to_data(answer_pointer, size, query_length, answer_count, auth_count);
        return *this;
    }

    void dns_package_builder::basic_query_package(reference ref, const char* domain)
    {
        ref.as_query().set_opcode(DNS_OPCODE_STAND_QUERY).set_RD().set_resp_RA();
        ref.set_query(domain).set_id(utils::rand_value());
    }

}  // namespace dns
