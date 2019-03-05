/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// test.cpp: test entry and function implements

#include "test.h"

#include "logging.h"

#include <random>

namespace test
{
    using std::random_device;

    rand_result random_value()
    {
        static std::random_device rd;
        return rd();
    }


    const CH* random_string(int len)
    {
        size_t actual_size;
        if (len <= 0) {
            actual_size = 10 + random_value() % 10;
        } else {
            actual_size = static_cast<size_t>(len);
        }
        CH* buffer = new CH[actual_size + 1];
        for (size_t t = 0; t < actual_size; t++) {
            buffer[t] = random_value() % ('z' - 'a') + 'a';
        }
        buffer[actual_size] = '\0';
        return buffer;
    }


}  // namespace test


#if !defined _WIN32 || !defined _WIN64
int main(int argc, char* argv[])
{
    logging::init_logging();
    logging::set_default_level(utils::LL_TRACE);
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    logging::destroy_logger();
    return ret;
}
#endif
