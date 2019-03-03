
#include "gtest/gtest.h"
#include "test.h"

#include "logging.h"

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
