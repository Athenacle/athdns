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
#include "server.h"

using namespace dns;

int main(int argc, CH* const argv[])
{
    utils::init_buffer_pool(128);

    global_server::init_local_udp_server_instance();
    logging::init_logging();
    utils::config_system(argc, argv);

    auto& server = global_server::get_server();

    server.init_local_udp_server();
    server.start_local_udp_server();

    global_server::destroy_local_udp_server_instance();
    utils::destroy_buffer();
    logging::destroy_logger();

    return 0;
}
