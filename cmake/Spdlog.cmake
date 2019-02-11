
FIND_PACKAGE(Threads REQUIRED)

# Enable ExternalProject CMake module
INCLUDE(ExternalProject)

# Download and install GoogleTest
ExternalProject_Add(
    spdlog
    URL https://github.com/gabime/spdlog/archive/v1.x.zip
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/spdlog
    # Disable install step
    CMAKE_ARGS "-DSPDLOG_BUILD_EXAMPLES=OFF;-DSPDLOG_BUILD_BENCH=OFF;-DSPDLOG_BUILD_TESTS=OFF"
    INSTALL_COMMAND ""
)

ExternalProject_Get_Property(spdlog source_dir binary_dir)


# I couldn't make it work with INTERFACE_INCLUDE_DIRECTORIES
INCLUDE_DIRECTORIES("${source_dir}/include/")
