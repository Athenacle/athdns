
#include "dns.h"

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
        ret          = static_cast<uint16_t>(ret << 8);
        ret += *(_ptr + 1);
        return ret;
    }

    bool responseIS(uint16_t flag, int offset)
    {
        return ((flag >> offset) & 0x1) == 1;
    }

}  // namespace

namespace dns
{
    using namespace dns_values;
    using namespace dns_utils;

    namespace dns_utils
    {
        int query_string_generator(const char* name,
                                   uint8_t* buffer,
                                   size_t buffer_size,
                                   uint8_t query_type,
                                   uint8_t query_class)
        {
            auto length = utils::strlen(name);
            if (buffer_size < length + 5) {
                return -1;
            }

            uint8_t* begin = buffer;
            memcpy(begin + 1, name, strlen(name) + 1);
            while (true) {
                uint8_t next_count = 0;
                uint8_t* p         = begin + 1;

                for (; *p != 0x0 && *p != '.'; p++) {
                    next_count++;
                }
                *begin = next_count;
                if (*p == 0x0) {
                    break;
                }
                begin = p;
            }
            buffer[length + 2] = 0;
            buffer[length + 3] = query_type;
            buffer[length + 4] = 0;
            buffer[length + 5] = query_class;
            return length + 6;
        }

        int query_string_generator(const Query& query, uint8_t* buffer, size_t buffer_size)
        {
            return query_string_generator(
                query.getName(), buffer, buffer_size, query.getType(), query.getClass());
        }

    }  // namespace dns_utils


    DnsPacket* DnsPacket::fromDataBuffer(uint8_t* _data, uint32_t _size)
    {
        auto buf = new uint8_t[_size];
        memcpy(buf, _data, _size);
        const auto ret = new DnsPacket;
        ret->_data     = buf;
        ret->_size     = _size;
        return ret;
    }

    DnsPacket::~DnsPacket()
    {
        delete[] _data;
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
        this->_id    = getQueryID();
        this->_flag  = getFlag();
        flag_pointer = _data + 2;
        auto query   = Query(_data + 12);
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


    Query::Query(uint8_t* _from)
    {
        _label_count     = 0;
        auto name_length = 0ul;
        auto ptr         = _from;
        do {
            _label_count++;
            name_length = name_length + *ptr + 1;
            ptr         = ptr + *ptr + 1;
        } while (*ptr != 0x00);
        name_length--;
        char* name_ptr = new char[name_length + 1];
        _name          = name_ptr;
        ptr            = _from;
        do {
            auto count = *ptr;
            ptr++;
            while (count > 0) {
                *name_ptr = *ptr;
                name_ptr++;
                ptr++;
                count--;
            }
            *name_ptr = '.';
            name_ptr++;
        } while (*ptr != 0x00);
        *(name_ptr - 1) = 0;

        _type  = getTwoByte(_from + name_length + 2);
        _class = getTwoByte(_from + name_length + 4);
    }

    Query::~Query()
    {
        delete[] _name;
    }

    const uint8_t Query::QUERY_CLASS_IN = 1;
    const uint8_t Query::QUERY_TYPE_A   = 1;


    // dns_package_builder

    dns_package_builder::dns_package_builder()
    {
        authority_pointer = answer_pointer = additional_pointer = query_pointer = nullptr;

        query_length = answer_length = addition_length = authority_length = 0;

        flag_pointer = header + 2;
        memset(header, 0, sizeof(header));
    }

    dns_package_builder::~dns_package_builder()
    {
        utils::strfree(query_pointer);
        utils::strfree(authority_pointer);
        utils::strfree(answer_pointer);
        utils::strfree(additional_pointer);
    }

    reference dns_package_builder::set_id(uint16_t id)
    {
        uint16_t* p = reinterpret_cast<uint16_t*>(header);
        *p          = id;
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
        assert(code >= 0 && code < 3);
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
        *ptr     = (*ptr & 0xf0) | rc;
        return *this;
    }

    reference dns_package_builder::set_query(const char* name)
    {
        const static size_t buffer_size     = 256;
        const static int query_count_offset = 5;
        static uint8_t buffer[buffer_size];
        query_length = query_string_generator(name, buffer, buffer_size);
        assert(header[query_count_offset] == 0);
        header[query_count_offset]++;
        query_pointer = utils::str_allocate<uint8_t>(query_length);
        memcpy(query_pointer, buffer, query_length * sizeof(uint8_t));
        return *this;
    }


    reference dns_package_builder::set_query(const Query& q)
    {
        const static size_t buffer_size     = 256;
        const static int query_count_offset = 5;
        static uint8_t buffer[buffer_size];
        query_length = query_string_generator(q, buffer, buffer_size);
        assert(header[query_count_offset] == 0);
        header[query_count_offset]++;
        query_pointer = utils::str_allocate<uint8_t>(query_length);
        memcpy(query_pointer, buffer, query_length * sizeof(uint8_t));
        return *this;
    }

    DnsPacket* dns_package_builder::build()
    {
        auto ret   = new DnsPacket;
        ret->_size = 12 + query_length + answer_length + authority_length + addition_length;
        auto data = ret->_data = new uint8_t[ret->_size];
        memcpy(data, header, 12);
        memcpy(data + 12, query_pointer, query_length);
        memcpy(data + 12 + query_length, answer_pointer, answer_length);
        memcpy(data + 12 + query_length + answer_length, authority_pointer, authority_length);
        memcpy(data + 12 + query_length + answer_length + authority_length,
               additional_pointer,
               addition_length);
        return ret;
    }

    reference dns_package_builder::add_record(record_node* r)
    {
        const int buffer_size = 256;
        static uint8_t buffer[buffer_size];
        int count      = 0;
        answer_length  = r->to_data(buffer, buffer_size, 0xc, count);
        answer_pointer = utils::str_allocate<uint8_t>(answer_length);
        memcpy(answer_pointer, buffer, answer_length * sizeof(uint8_t));
        uint16_t* answer_rr_pointer = reinterpret_cast<uint16_t*>(header) + 3;
        *answer_rr_pointer          = htons(count);
        return *this;
    }
}  // namespace dns
