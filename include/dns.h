/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// dns.h: DNS diagram parser header

#ifndef DNS_H
#define DNS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "athdns.h"
#include "record.h"

#include <cassert>
#include <cinttypes>

namespace dns
{
    namespace dns_values
    {
        const uint16_t DNS_TYPE_A = 1;       // a host address
        const uint16_t DNS_TYPE_NS = 2;      // an authoritative name server
        const uint16_t DNS_TYPE_MD = 3;      // a mail destination (Obsolete - use MX)
        const uint16_t DNS_TYPE_MF = 4;      // a mail forwarder (Obsolete - use MX)
        const uint16_t DNS_TYPE_CNAME = 5;   // the canonical name for an alias
        const uint16_t DNS_TYPE_SOA = 6;     // marks the start of a zone of authority
        const uint16_t DNS_TYPE_MB = 7;      // a mailbox domain name (EXPERIMENTAL)
        const uint16_t DNS_TYPE_MG = 8;      // a mail group member (EXPERIMENTAL)
        const uint16_t DNS_TYPE_MR = 9;      // a mail rename domain name (EXPERIMENTAL)
        const uint16_t DNS_TYPE_NULL = 10;   // a null RR (EXPERIMENTAL)
        const uint16_t DNS_TYPE_WKS = 11;    // a well known service description
        const uint16_t DNS_TYPE_PTR = 12;    // a domain name pointer
        const uint16_t DNS_TYPE_HINFO = 13;  // host information
        const uint16_t DNS_TYPE_MINFO = 14;  // mailbox or mail list information
        const uint16_t DNS_TYPE_MX = 15;     // mail exchange
        const uint16_t DNS_TYPE_TXT = 16;    // text strings


        //dns reply code
        const uint8_t DNS_RCODE_NOERROR = 0x0;   //No error; successful update.
        const uint8_t DNS_RCODE_FORMERR = 0x1;   //Format error
        const uint8_t DNS_RCODE_SERVFAIL = 0x2;  //DNS server encountered an internal error
        const uint8_t DNS_RCODE_NXDOMAIN = 0x3;  //A name that should exist does not exist.
        const uint8_t DNS_RCODE_NOTIMP = 0x4;    //DNS server does not support the specified OpCode.
        const uint8_t DNS_RCODE_REFUSED = 0x5;   //DNS server refuses to perform the update.
        const uint8_t DNS_RCODE_YXDOMAIN = 0x6;  //A name that should not exist does exist.

        //A resource record set that should not exist does exist.
        const uint8_t DNS_RCODE_YXRRSET = 0x7;
        //A resource record set that should exist does not exist.
        const uint8_t DNS_RCODE_NXRRSET = 0x8;
        //DNS server is not authoritative for the zone named in the Zone section.
        const uint8_t DNS_RCODE_NOTAUTH = 0x9;
        //A name used in the Prerequisite or Update sections is not within the zone specified by the Zone section.
        const uint8_t DNS_RCODE_NOTZONE = 0xa;

        const uint8_t DNS_OPCODE_STAND_QUERY = 0;
        const uint8_t DNS_OPCODE_REVERSE = 1;
        const uint8_t DNS_OPCODE_SERVER_STATUS = 2;

        const uint16_t DNS_CLASS_IN = 0x1;

        const char DNS_OPCODE[][25] = {
            "OPCode: Standard Query",  // 0
            "OPCode: Reverse Query",   // 1
            "OPCode: Server Status"    // 2
        };


        const int DNS_FLAGS_BIT_QUERY = 0;

        const int DNS_FLAGS_RESP_AA = 5;
        const int DNS_FLAGS_BIT_TC = 6;
        const int DNS_FLAGS_BIT_RD = 7;
        const int DNS_FLAGS_RESP_RA = 8;

        const int DNS_FLAGS_RESP_ANSWER_AUTHENTICATED = 10;
        const int DNS_FLAGS_RESP_NON_AUTHENTICATED = 11;


        const int DNS_FORMAT_HEADER_LENGTH = 12;
        const int DNS_FORMAT_ANSWER_VALUE_OFFSET = 12;

    }  // namespace dns_values


    /*
     * bit_is_set:
     *    one  byte: 0x 1  1  1  1  1  1  1  1
     *    position :    0  1  2  3  4  5  6  7
     */

    inline bool bit_is_set(uint8_t num, int offset)
    {
        assert(offset >= 0 && offset < 8);
        return ((num >> (8 - offset - 1)) & 0x1) == 1;
    }

    inline void bit_set(uint8_t *num, int count, bool set = true)
    {
        assert(count >= 0 && count < 8);
        uint8_t mask = 0x1 << (8 - count - 1);
        if (likely(set)) {
            *num = *num | mask;
        } else {
            mask = ~mask;
            *num = *num & mask;
        }
    }

    inline bool flag_is_set(uint8_t *flags, int flag)
    {
        assert(flag >= 0 && flag < 16);
        if (flag >= 8) {
            return bit_is_set(*(flags + 1), flag % 8);
        } else {
            return bit_is_set(*flags, flag);
        }
    }

    inline void flag_set(uint8_t *flags, int flag, bool set = true)
    {
        assert(flag >= 0 && flag < 16);
        if (flag >= 8) {
            bit_set((flags + 1), flag % 8, set);
        } else {
            bit_set(flags, flag, set);
        }
    }

    namespace dns_utils
    {
        const char *query_string_parser(uint8_t *, uint8_t * = nullptr);
        //const char *query_string_parser(uint8_t *);

        const uint8_t *query_string_generator(const char *);

        int query_string_generator(const char *, uint8_t *, size_t);

        bool ip_string_to_uint32(const char *, uint32_t &);
    }  // namespace dns_utils


    class query
    {
        uint16_t type;
        uint16_t clazz;

        const char *name;

    public:
        static const uint8_t QUERY_TYPE_A;
        static const uint8_t QUERY_CLASS_IN;

        static int query_section_builder(
            domain_name dname, uint8_t *buf, size_t buf_size, uint16_t type, uint16_t clazz);

        static int query_section_builder(const query &query, uint8_t *buf, size_t buf_size);

        explicit query(uint8_t *);

        query(const char *name, uint16_t type, uint16_t clazz)
            : type(type), clazz(clazz), name(name)
        {
        }

        query()
        {
            type = clazz = 0;
            name = nullptr;
        }

        ~query();

        uint16_t getType() const
        {
            return type;
        }

        uint16_t getClass() const
        {
            return clazz;
        }

        const char *getName() const
        {
            return name;
        }
    };

    enum class dns_parse_status {
        request_ok,
        response_ok,
        format_error,
        query_type_error,
        query_class_error,
        query_name_error,
        number_error
    };

    class dns_packet
    {
        friend class dns_package_builder;

    private:
        uint8_t *data;
        uint32_t size;

        uint8_t *flag_pointer;

        uint16_t id;
        uint16_t flag;

        bool parsed;

        dns_packet()
        {
            id = flag = 0xffff;
            size = 0;
            data = nullptr;
            parsed = false;
        }

        void test_flag() const
        {
            assert(flag != 0xffff);
        }

        query this_query;

        void swap(dns_packet &&);

    public:
        ~dns_packet();

        static dns_packet *fromDataBuffer(const uv_buf_t *, dns_parse_status &);

        static dns_packet *fromDataBuffer(uint8_t *, uint32_t);
        static dns_packet *fromDataBuffer(uv_buf_t *);

        static dns_packet *build_response_with_records(dns_packet *, record_node *);

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

        uint32_t get_size() const
        {
            return size;
        }

        uint8_t *get_data() const
        {
            return data;
        }


        const query &getQuery() const
        {
            return this_query;
        }

        bool isAA() const;
        bool isTC() const;
        bool isRD() const;
        bool isRA() const;
        bool isAD() const;

        record_node *generate_record_node();
    };

    using reference = dns_package_builder &;

    class dns_package_builder
    {
        uint8_t *builder_buffer;

        uint8_t header[12];
        uint8_t *flag_pointer;

        uint8_t *query_pointer;
        int query_length;

        uint8_t *buffer;

        uint32_t rdata_length;
        uint8_t *rdata;

        static uint8_t *buffer_allocate(size_t);
        static void buffer_destroy(uint8_t *);

        uint16_t answer_count;
        uint16_t auth_count;

    public:
        dns_package_builder();
        ~dns_package_builder();

        reference set_id(uint16_t);

        reference as_query();
        reference as_response();

        reference set_opcode(uint8_t);
        reference set_TC();
        reference set_resp_AA();
        reference set_RD();
        reference set_resp_RA();
        reference set_resp_AnswerAuthenicated();
        reference set_reply_code(uint8_t);

        reference set_query(const char *);
        reference set_query(uint8_t *, int);
        reference set_query(const query &);

        reference add_record(record_node *);

        dns_packet *build();

        static void basic_query_package(reference, const char *);
    };

}  // namespace dns

#endif
