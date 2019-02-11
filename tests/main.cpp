#include "gtest/gtest.h"
#include "test.h"

#if !defined _WIN32 || !defined _WIN64
int main(int argc, char* argv[])
{
    //    test::init_tests();
    //   int _argc = argc + 1;
    //   char** _argv = new char*[argc + 2];
    //   int t = 0;
    //   for (t = 0; t < argc; t++) {
    //       _argv[t] = strdup(argv[t]);
    //     }
    //     auto pointer = _argv[argc] = strdup("--gtest_shuffle");
    //     _argv[argc + 1] = nullptr;
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    //  for (t = 0; t < _argc + 2; t++) {
    //  free(_argv[t]);
    //  }
    //  free(pointer);
    //  delete[] _argv;
    //  StringBuilder::destroyGlobalFormatBuffer();
    //  delete[] test::test_file;
    return ret;
}
#endif
