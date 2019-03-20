/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// utils_test.cpp: tests for utils

#include "test.h"

#include "athdns.h"
#include "utils.h"

#include <bitset>

using namespace utils;
using std::bitset;
using std::vector;
using utils::bit_container;


#define ARRAY_SPLIT_TEST(len, c)                     \
    do {                                             \
        vector<string> arrays;                       \
        split(arrays, str.c_str(), c);               \
        EXPECT_EQ(arrays.size(), len);               \
        for (size_t i = 0; i < arrays.size(); i++) { \
            EXPECT_EQ(data[i], arrays[i]);           \
        }                                            \
    } while (false);


TEST(utils, alloctorVSnew)
{
    struct simple {
        int t;
        char buf[256];
        long long *p;
        bool b;
        long long la[10];
    };

    const int count = 10000;
    simple **array = new simple *[count];

    std::vector<simple *> vec;
    utils::allocator_pool<simple> spool(20000);

    time_object begin;
    for (int i = 0; i < count; i++) {
        simple *p = spool.allocate();
        array[i] = p;
    }
    for (int i = 0; i < count; i++) {
        spool.deallocate(array[i]);
    }
    time_object end;
    vec.clear();
    auto alloctimeuse = time_object::diff_to_ms(begin, end);

    time_object ndbegin;
    for (int i = 0; i < count; i++) {
        simple *p = new simple;
        array[i] = p;
    }
    for (int i = 0; i < count; i++) {
        delete (array[i]);
    }
    time_object ndend;

    auto nduse = time_object::diff_to_ms(ndbegin, ndend);

    char op = alloctimeuse > nduse ? '>' : '<';

    std::cout << "allocator: " << alloctimeuse << " " << op << " nd: " << nduse << std::endl;
    delete[] array;
}

TEST(utils, split)
{
    {
        string str = PRE("1.2.3.4.5.6.7.8");
        const CH data[][2] = {
            PRE("1"),
            PRE("2"),
            PRE("3"),
            PRE("4"),
            PRE("5"),
            PRE("6"),
            PRE("7"),
            PRE("8"),
        };
        ARRAY_SPLIT_TEST(8ul, '.');
    }
    {
        string str = PRE("This is an apple.");
        const CH data[][7] = {PRE("This"), PRE("is"), PRE("an"), PRE("apple.")};
        ARRAY_SPLIT_TEST(4ul, ' ');
    }
    {
        string str = PRE("This is an apple.");
        const CH data[][20] = {PRE("This is an apple.")};
        ARRAY_SPLIT_TEST(1ul, '#');
    }
    {
        string str = PRE("This is an apple.");
        const CH data[][20] = {PRE("This is an apple")};
        ARRAY_SPLIT_TEST(1ul, '.');
    }
    {
        string str = PRE("apple");
        const CH data[][5] = {PRE("a"), PRE(""), PRE("le")};
        ARRAY_SPLIT_TEST(3ul, 'p');
    }
}

#undef ARRAY_SPLIT_TEST


TEST(utils, bit_container)
{
    const int size = 102400;

    bitset<size> bs;
    bit_container bc(size);

    for (size_t i = 0; i < size; i++) {
        bool b = test::random_value() % 2 == 0;
        bc.set(i, b);
        bs.set(i, b);
        ASSERT_EQ(bs.test(i), bc.test(i)) << i;
    }

    for (size_t i = 0; i < size; i++) {
        ASSERT_EQ(bs.test(i), bc.test(i)) << i;
    }
}

#ifdef HAVE_DOH_SUPPORT

TEST(utils, base64Encode)
{
    struct pair {
        const char *base;
        const char *base64;
        size_t len;
    };

    pair pairs[] = {{.base = "\n", .base64 = "Cg==", .len = 1},
                    {.base = "12345", .base64 = "MTIzNDU=", .len = 5},
                    {.base = "encode_base64", .base64 = "ZW5jb2RlX2Jhc2U2NA==", .len = 13},
                    {.base = "\1\2\3\4\5", .base64 = "AQIDBAU=", .len = 5},
                    {.base = "\1\2\3\4\5\0", .base64 = "AQIDBAU=", .len = 5}};

    for (auto &p : pairs) {
        auto res = utils::encode_base64(p.base, p.len);
        auto res2 = utils::encode_base64(p.base);
        EXPECT_STREQ(res2, p.base64) << p.base;
        EXPECT_STREQ(res, p.base64) << p.base;
        utils::strfree(res);
        utils::strfree(res2);
    }
}

#endif

TEST(utils, time_object)
{
    using utils::time_object;
    const int sleep_time = 1;
    time_object begin;
    sleep(sleep_time);
    time_object end;

    uint64_t nano = time_object::diff_to_ns(begin, end);
    double nano_percent = nano / 1000000000.0;
    EXPECT_FLOAT_EQ(nano_percent, sleep_time);

    double us = time_object::diff_to_us(begin, end);
    EXPECT_FLOAT_EQ(us, sleep_time * 1000000.0);

    double ms = time_object::diff_to_ms(begin, end);
    EXPECT_FLOAT_EQ(ms, sleep_time * 1000.0);
}
