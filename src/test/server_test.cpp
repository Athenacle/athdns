/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// server_test.cpp

#include "test.h"

#include "server.h"

#ifdef BUILD_ROOT

TEST(server, sync_internal_query_A)
{
    const char site[] = "www.example.org";
    int count = 0;
    auto weo = test::system_query_A(site, count);
    auto ips = global_server::get_server().sync_internal_query_A(site);
    ASSERT_TRUE(weo != nullptr);
    ASSERT_TRUE(ips != nullptr);
    bool exists = false;
    for (int i = 0; i < count; i++) {
        if (weo[i]->operator==(ips->get_address())) {
            exists = true;
        }
    }
    EXPECT_TRUE(exists);

    for (int i = 0; i < count; i++) {
        delete weo[i];
    }
    delete[] weo;
    delete ips;
}

#endif
