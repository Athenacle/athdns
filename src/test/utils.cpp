
#include "test.h"

#include "athdns.h"
#include "utils.h"

#include <sys/time.h>

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
    timeval allocator_begin;
    gettimeofday(&allocator_begin, nullptr);

    for (int i = 0; i < count; i++) {
        simple *p = spool.allocate();
        array[i] = p;
    }
    for (int i = 0; i < count; i++) {
        spool.deallocate(array[i]);
    }
    timeval allocator_end;
    gettimeofday(&allocator_end, nullptr);
    vec.clear();
    double alloctimeuse = 1000000.0 * (allocator_end.tv_sec - allocator_begin.tv_sec)
                          + allocator_end.tv_usec - allocator_begin.tv_usec;
    timeval nd_begin;
    gettimeofday(&nd_begin, nullptr);

    for (int i = 0; i < count; i++) {
        simple *p = new simple;
        array[i] = p;
    }
    for (int i = 0; i < count; i++) {
        delete (array[i]);
    }
    timeval nd_end;
    gettimeofday(&nd_end, nullptr);

    double nduse =
        1000000.0 * (nd_end.tv_sec - nd_begin.tv_sec) + nd_end.tv_usec - nd_begin.tv_usec;

    char op = alloctimeuse > nduse ? '>' : '<';

    std::cout << "allocator: " << alloctimeuse / 1000000 << " " << op << " nd: " << nduse / 1000000
              << std::endl;
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
