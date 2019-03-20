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
#include "server.h"

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

    ip_address** system_query_A(const char* domain, int& count)
    {
        if (domain == nullptr) {
            return nullptr;
        }
        count = 0;
        hostent* ht;
        ip_address** ret = nullptr;
        ht = gethostbyname(domain);
        if (ht != nullptr) {
            std::vector<char*> dots;
            if (ht->h_addrtype == AF_INET) {
                char** list = ht->h_addr_list;
                for (auto p = list; *p != nullptr; p++) {
                    char* dest = new char[20];
                    if (inet_ntop(AF_INET, *p, dest, 20) != nullptr) {
                        dots.emplace_back(dest);
                    } else {
                        delete[] dest;
                    }
                }
            }
            ret = new ip_address*[dots.size()];
            for (size_t i = 0; i < dots.size(); i++) {
                uint32_t ip;
                if (utils::check_ip_address(dots[i], ip)) {
                    ret[i] = new ip_address(ip);
                    count++;
                }
                delete[] dots[i];
            }
        }
        return ret;
    }


}  // namespace test

#ifdef BUILD_ROOT
namespace
{
    struct combined_testing {
        char** argv;
        pthread_barrier_t* barrier;
        pthread_t pthread;
        bool started;
    };

    struct combined_testing* test_obj = nullptr;
}  // namespace

#endif

void* combined_test_startup(void*)
{
#if defined BUILD_ROOT
    WARN("starting global_server");
    const char test_conf_file[] = BUILD_ROOT "/src/test/test.conf";
    test_obj->argv[0] = utils::str_dump(PROJECT_NAME);
    test_obj->argv[1] = utils::str_dump(test_conf_file);
    if (access(test_conf_file, R_OK) == 0) {
        global_server::init_instance();
        utils::config_system(2, test_obj->argv);
        utils::init_buffer_pool(512);
        auto& s = global_server::get_server();
        s.init_server();
        pthread_barrier_wait(test_obj->barrier);
        test_obj->started = true;
        s.start_server();
    }
#endif
    return nullptr;
}

void stop_test_server()
{
#ifdef BUILD_ROOT
    if (test_obj->started) {
        global_server::get_server().do_stop();
        pthread_join(test_obj->pthread, nullptr);
        global_server::destroy_server();
        utils::destroy_buffer();
        pthread_barrier_destroy(test_obj->barrier);
        delete test_obj->barrier;
    }
    delete[] test_obj->argv[0];
    delete[] test_obj->argv[1];
    delete[] test_obj->argv;
    delete test_obj;
#endif
}


#if !defined _WIN32 || !defined _WIN64
int main(int argc, char* argv[])
{
    logging::init_logging();
#ifdef BUILD_ROOT
    test_obj = new combined_testing;
    test_obj->argv = new char*[2];
    test_obj->started = false;
    test_obj->barrier = new pthread_barrier_t;
    pthread_barrier_init(test_obj->barrier, nullptr, 2);
    pthread_create(&test_obj->pthread, nullptr, combined_test_startup, nullptr);
    pthread_barrier_wait(test_obj->barrier);
#endif

    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

    stop_test_server();
    logging::destroy_logger();

    return ret;
}
#endif
