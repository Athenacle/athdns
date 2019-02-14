
#include "dnsserver.h"
#include "test.h"

using namespace utils;
using std::vector;

#define ARRAY_SPLIT_TEST(len, c)                     \
    do {                                             \
        vector<string> arrays;                       \
        split(arrays, str.c_str(), c);               \
        EXPECT_EQ(arrays.size(), len);               \
        for (size_t i = 0; i < arrays.size(); i++) { \
            EXPECT_EQ(data[i], arrays[i]);           \
        }                                            \
    } while (false);

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
