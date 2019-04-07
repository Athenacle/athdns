/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// dns_record_test.cpp: tests for record_node

#include "test.h"

#include "dns.h"

using namespace dns;
using namespace dns_utils;
using namespace dns_values;

TEST(DNS_record, to_data_1)
{
    // www.office.com
    uint8_t packet_bytes[] = {
        0xba, 0xcb, 0x81, 0x80, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77,
        0x77, 0x06, 0x6f, 0x66, 0x66, 0x69, 0x63, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x02, 0x2a, 0x00, 0x1c, 0x03,
        0x67, 0x65, 0x6f, 0x04, 0x68, 0x6f, 0x6d, 0x65, 0x06, 0x6f, 0x66, 0x66, 0x69, 0x63, 0x65,
        0x06, 0x61, 0x6b, 0x61, 0x64, 0x6e, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0, 0x2c, 0x00,
        0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x0d, 0x0a, 0x6e, 0x6f, 0x6e, 0x75, 0x73,
        0x5f, 0x65, 0x64, 0x67, 0x65, 0xc0, 0x30, 0xc0, 0x54, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x2c, 0x00, 0x25, 0x12, 0x68, 0x6f, 0x6d, 0x65, 0x2d, 0x6f, 0x66, 0x66, 0x69, 0x63,
        0x65, 0x33, 0x36, 0x35, 0x2d, 0x63, 0x6f, 0x6d, 0x06, 0x62, 0x2d, 0x30, 0x30, 0x30, 0x34,
        0x08, 0x62, 0x2d, 0x6d, 0x73, 0x65, 0x64, 0x67, 0x65, 0xc0, 0x43, 0xc0, 0x6d, 0x00, 0x05,
        0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x02, 0xc0, 0x80, 0xc0, 0x80, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x0d, 0x6b, 0x06, 0x9c};

    dns_packet *pack = dns_packet::fromDataBuffer(packet_bytes, sizeof(packet_bytes));
    pack->parse();

    record_node *node = pack->generate_record_node();

    dns_package_builder builder;
    builder.as_response().set_query(pack->getQuery());

    builder.add_record(node);

    if (pack->isRD()) {
        builder.set_RD().set_resp_RA();
    }

    builder.set_id(pack->getQueryID()).set_opcode(DNS_OPCODE_STAND_QUERY);

    dns_packet *result = builder.build();
    result->parse();

    ASSERT_EQ(result->get_size(), pack->get_size());
    ASSERT_EQ(result->get_size(), sizeof(packet_bytes));
    EXPECT_TRUE(memcmp(result->get_data(), packet_bytes, sizeof(packet_bytes)) == 0);
    delete result;
    delete pack;
    delete node;
}

TEST(DNS_record, to_data_2)
{
    // sql.athenacle.xyz -> files -> git -> master -> 10.70.20.11
    uint8_t packet_bytes[] = {
        0x6b, 0x3a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x73,
        0x71, 0x6c, 0x09, 0x61, 0x74, 0x68, 0x65, 0x6e, 0x61, 0x63, 0x6c, 0x65, 0x03, 0x78,
        0x79, 0x7a, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00,
        0x00, 0x01, 0x2b, 0x00, 0x08, 0x05, 0x66, 0x69, 0x6c, 0x65, 0x73, 0xc0, 0x10, 0xc0,
        0x2f, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x06, 0x03, 0x67, 0x69,
        0x74, 0xc0, 0x10, 0xc0, 0x43, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00,
        0x09, 0x06, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0xc0, 0x10, 0xc0, 0x55, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x01, 0x51, 0x7f, 0x00, 0x04, 0x0a, 0x46, 0x14, 0x0b};

    dns_packet *pack = dns_packet::fromDataBuffer(packet_bytes, sizeof(packet_bytes));
    pack->parse();
    record_node *node = pack->generate_record_node();

    dns_package_builder builder;
    builder.as_response().set_query(pack->getQuery()).add_record(node);
    if (pack->isRD()) {
        builder.set_RD().set_resp_RA();
    }
    builder.set_id(pack->getQueryID()).set_opcode(DNS_OPCODE_STAND_QUERY);

    dns_packet *result = builder.build();
    result->parse();

    ASSERT_EQ(result->get_size(), pack->get_size());
    ASSERT_EQ(result->get_size(), sizeof(packet_bytes));
    EXPECT_TRUE(memcmp(result->get_data(), packet_bytes, sizeof(packet_bytes)) == 0);
    delete result;
    delete pack;
    delete node;
}

namespace
{
    int data_to_dns_value(uint8_t *begin, uint8_t *end, std::vector<dns_value> &out)
    {
        int i = 0;
        dns_value v;
        for (; begin < end;) {
            begin = dns_value::from_data(begin, end, v);
            if (begin == nullptr) {
                break;
            } else {
                i++;
                out.emplace_back(std::move(v));
            }
        }
        return i;
    }

    void test_swap_all_A()
    {
        uint8_t data[] = {
            "\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x74\x00\x04\x01\x02\x03\x01"
            "\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x74\x00\x04\x01\x02\x03\x02"
            "\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x74\x00\x04\x01\x02\x03\x03"
            "\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x74\x00\x04\x01\x02\x03\x04"
            "\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x74\x00\x04\x01\x02\x03\x05"
            "\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x74\x00\x04\x01\x02\x03\x06"};
        std::vector<dns_value> ves;
        ip_address *ip;
        auto count = data_to_dns_value(data, data + sizeof(data) - 1, ves);

        ASSERT_TRUE(ves.size() == 6);
        ASSERT_EQ(count, 6);
        record_node node("test.");
        node.set_answers(ves);

        uint32_t ips[] = {0x01020301,
                          0x01020306,
                          0x01020305,
                          0x01020304,
                          0x01020303,
                          0x01020302,
                          0x01020301,
                          0x01020306};

        string s;
        for (int i = 0; i <= count + 1; i++) {
            s.clear();
            ip = node.get_record_A();
            node.swap_A();
            ip->to_string(s);
            EXPECT_TRUE(ip->get_address() == ips[i]) << s << " " << i;
            delete ip;
        }
    }

    void test_swap_all_CNAME()
    {
        uint8_t data[] = {
            "\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x7a\x00\x05\x02\x76\x32\xc0\x10"
            "\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x7a\x00\x05\x02\x76\x33\xc0\x10"};
        std::vector<dns_value> ves;
        ip_address *ip;
        auto count = data_to_dns_value(data, data + sizeof(data) - 1, ves);
        ASSERT_TRUE(count == 2);
        ASSERT_TRUE(ves.size() == 2);
        record_node n("test");
        n.set_answers(ves);

        uint8_t buffer[sizeof(data) - 1];

        for (int i = 0; i < 4; i++) {
            ip = n.get_record_A();
            n.swap_A();
            ASSERT_TRUE(ip == nullptr);
            n.to_data(buffer);
            ASSERT_TRUE(memcmp(buffer, data, sizeof(data) - 1) == 0);
        }
    }

    void test_swap_some_A_some_CNAME()
    {
        uint8_t data[] = {
            "\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x7a\x00\x05\x02\x76\x32\xc0\x10"
            "\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x7a\x00\x05\x02\x76\x33\xc0\x10"
            "\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x74\x00\x04\x01\x02\x03\x01"
            "\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x74\x00\x04\x01\x02\x03\x02"};
        std::vector<dns_value> ves;
        ip_address *ip;
        auto count = data_to_dns_value(data, data + sizeof(data) - 1, ves);
        ASSERT_TRUE(count == 4);
        ASSERT_TRUE(ves.size() == 4);
        record_node n("test");
        n.set_answers(ves);

        uint32_t ips[] = {0x01020301, 0x01020302};

        for (int i = 0; i < 4; i++) {
            string s;
            ip = n.get_record_A();
            n.swap_A();
            ASSERT_TRUE(ip != nullptr);
            ip->to_string(s);
            ASSERT_TRUE(ip->operator==(ips[i % 2])) << s;
        }
    }

}  // namespace

TEST(DNS_record, swap)
{
    test_swap_all_A();
    test_swap_all_CNAME();
    test_swap_some_A_some_CNAME();
}
