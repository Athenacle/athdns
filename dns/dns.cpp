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
        ret = static_cast<uint16_t>(ret << 8);
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
    DnsPacket* DnsPacket::fromDataBuffer(uint8_t* _data, uint32_t _size)
    {
        auto buf = new uint8_t[_size];
        memcpy(buf, _data, _size);
        const auto ret = new DnsPacket;
        ret->_data = buf;
        ret->_size = _size;
        return ret;
    }

    DnsPacket::~DnsPacket()
    {
        delete[] _data;
    }


    uint16_t DnsPacket::getQueryID() const
    {
        return getTwoByte(_data);
    }

    uint16_t DnsPacket::getFlag() const
    {
        return getTwoByte(_data + 2);
    }

    void DnsPacket::parse()
    {
        this->_id = getQueryID();
        this->_flag = getFlag();
        auto query = Query(_data + 12);
        std::swap(this->_query, query);
    }

    bool DnsPacket::isQuery() const
    {
        assert(_flag != 0);
        const auto resp = _flag >> 15;
        return resp == 0;
    }

    bool DnsPacket::isResponse() const
    {
        return !isQuery();
    }

    uint8_t DnsPacket::getOPCode() const
    {
        testFlagSet();
        return (_flag >> 11) & 0x0f;
    }


    bool DnsPacket::isAA() const
    {
        testFlagSet();
        return isResponse() && responseIS(_flag, 10);
    }

    bool DnsPacket::isTC() const
    {
        testFlagSet();
        return isResponse() && responseIS(_flag, 9);
    }

    bool DnsPacket::isRD() const
    {
        testFlagSet();
        return isResponse() && responseIS(_flag, 8);
    }

    bool DnsPacket::isRA() const
    {
        testFlagSet();
        return isResponse() && responseIS(_flag, 7);
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

    Query::Query(uint8_t* _from)
    {
        _label_count = 0;
        auto name_length = 0ul;
        auto ptr = _from;
        do {
            _label_count++;
            name_length = name_length + *ptr + 1;
            ptr = ptr + *ptr + 1;
        } while (*ptr != 0x00);
        name_length--;
        char* name_ptr = new char[name_length + 1];
        _name = name_ptr;
        ptr = _from;
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

        _type = getTwoByte(_from + name_length + 2);
        _class = getTwoByte(_from + name_length + 4);
    }

    Query::~Query()
    {
        delete[] _name;
    }

    const uint8_t Query::QUERY_CLASS_IN = 1;
    const uint8_t Query::QUERY_TYPE_A = 1;

}  // namespace dns
