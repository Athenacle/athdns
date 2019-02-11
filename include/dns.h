#pragma once

#ifndef DNS_H
#define DNS_H

#include <cinttypes>

#define DEBUG
#include <cassert>

namespace dns
{
    namespace dns_values
    {
        const uint8_t DNS_TYPE_A     = 1;   // a host address
        const uint8_t DNS_TYPE_NS    = 2;   // an authoritative name server
        const uint8_t DNS_TYPE_MD    = 3;   // a mail destination (Obsolete - use MX)
        const uint8_t DNS_TYPE_MF    = 4;   // a mail forwarder (Obsolete - use MX)
        const uint8_t DNS_TYPE_CNAME = 5;   // the canonical name for an alias
        const uint8_t DNS_TYPE_SOA   = 6;   // marks the start of a zone of authority
        const uint8_t DNS_TYPE_MB    = 7;   // a mailbox domain name (EXPERIMENTAL)
        const uint8_t DNS_TYPE_MG    = 8;   // a mail group member (EXPERIMENTAL)
        const uint8_t DNS_TYPE_MR    = 9;   // a mail rename domain name (EXPERIMENTAL)
        const uint8_t DNS_TYPE_NULL  = 10;  // a null RR (EXPERIMENTAL)
        const uint8_t DNS_TYPE_WKS   = 11;  // a well known service description
        const uint8_t DNS_TYPE_PTR   = 12;  // a domain name pointer
        const uint8_t DNS_TYPE_HINFO = 13;  // host information
        const uint8_t DNS_TYPE_MINFO = 14;  // mailbox or mail list information
        const uint8_t DNS_TYPE_MX    = 15;  // mail exchange
        const uint8_t DNS_TYPE_TXT   = 16;  // text strings


        const uint8_t DNS_RCODE_NOERROR  = 0x0;  //No error; successful update.
        const uint8_t DNS_RCODE_FORMERR  = 0x1;  //Format error
        const uint8_t DNS_RCODE_SERVFAIL = 0x2;  //DNS server encountered an internal error
        const uint8_t DNS_RCODE_NXDOMAIN = 0x3;  //A name that should exist does not exist.
        const uint8_t DNS_RCODE_NOTIMP   = 0x4;  //DNS server does not support the specified OpCode.
        const uint8_t DNS_RCODE_REFUSED  = 0x5;  //DNS server refuses to perform the update.
        const uint8_t DNS_RCODE_YXDOMAIN = 0x6;  //A name that should not exist does exist.

        //A resource record set that should not exist does exist.
        const uint8_t DNS_RCODE_YXRRSET = 0x7;
        //A resource record set that should exist does not exist.
        const uint8_t DNS_RCODE_NXRRSET = 0x8;
        //DNS server is not authoritative for the zone named in the Zone section.
        const uint8_t DNS_RCODE_NOTAUTH = 0x9;
        //A name used in the Prerequisite or Update sections is not within the zone specified by the Zone section.
        const uint8_t DNS_RCODE_NOTZONE = 0xa;


        const uint8_t DNS_OPCODE_STAND_QUERY   = 0;
        const uint8_t DNS_OPCODE_REVERSE       = 1;
        const uint8_t DNS_OPCODE_SERVER_STATUS = 2;

        const char DNS_OPCODE[][25] = {
            "OPCode: Standard Query",  // 0
            "OPCode: Reverse Query",   // 1
            "OPCode: Server Status"    // 2
        };
    }  // namespace dns_values

    class Query
    {
        uint16_t _type;
        uint16_t _class;

        const char *_name;
        uint8_t _label_count;

    public:
        static const uint8_t QUERY_TYPE_A;
        static const uint8_t QUERY_CLASS_IN;

        explicit Query(uint8_t *);
        Query()
        {
            _type = _class = _label_count = 0;
            _name                         = nullptr;
        }

        ~Query();

        uint16_t getType() const
        {
            return _type;
        }
        uint16_t getClass() const
        {
            return _class;
        }
        uint8_t getLabelCount() const
        {
            return _label_count;
        }
        const char *getName() const
        {
            return _name;
        }
    };

    class DnsPacket
    {
    private:
        uint8_t *_data;
        uint32_t _size;

        uint16_t _id;
        uint16_t _flag;


        DnsPacket()
        {
            _id = _flag = 0xffff;
            _size       = 0;
            _data       = nullptr;
        }

        void testFlagSet() const
        {
#ifdef DEBUG
            assert(_flag != 0xffff);
#endif
        }
        Query _query;

    public:
        ~DnsPacket();


        static DnsPacket *fromDataBuffer(uint8_t *, uint32_t);

        uint16_t getQueryID() const;
        uint16_t getFlag() const;

        void parse();

        bool isQuery() const;
        bool isResponse() const;
        uint8_t getOPCode() const;
        uint8_t getReturnCode() const;

        uint16_t getQuestionCount() const;
        uint16_t getAnswerRRCount() const;
        uint16_t getAuthorityRRCount() const;
        uint16_t getAdditionalRRCount() const;

        const Query &getQuery() const
        {
            return _query;
        }

        bool isAA() const;
        bool isTC() const;
        bool isRD() const;
        bool isRA() const;
    };

}  // namespace dns

#endif
