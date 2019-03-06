/*
 * Copyright (c) 2019 WangXiao <zjjhwxc@gmail.com>
 *
 * This Project is licensed under the MIT License.
 * Please refer to LICENSE file at root directory for more information
 *
 * athdns: simple DNS forwarder
 *
 */

// main.cpp: main entry for athdns

#include "athdns.h"
#include "logging.h"
#include "objects.h"
#include "server.h"

using namespace dns;

void atexit_handler();


int main(int argc, CH* const argv[])
{
    global_server::init_instance();
    logging::init_logging();
    utils::config_system(argc, argv);
    utils::init_buffer_pool(1024);

    auto& server = global_server::get_server();

    server.init_server();
    server.start_server();

    global_server::destroy_server();
    utils::destroy_buffer();
    logging::destroy_logger();

    return 0;
}
