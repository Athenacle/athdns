
cmake_minimum_required(VERSION 3.4)

project(athdns C CXX)

option(ATHDNS_ENABLE_TEST "Enable Testing" OFF)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)
set(ATHDNS_INCLUDE_ROOT ${CMAKE_SOURCE_DIR}/include/)

set(CMAKE_CXX_STANDARD 14)
set(PROJECT_NAME athdns)
set(PROJECT_VERSION 0.0.0)

string(TIMESTAMP ATHDNS_BUILD_TIME "%Y-%m-%d %H:%M:%SZ")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(UNIX)
  set(ATHDNS_BUILD_ON_UNIX "Build ON UNIX" ON)
  set(ATHDNS_BUILD_ON_WINDOWS OFF)
else()
  if(WINDOWS)
    set(ATHDNS_BUILD_ON_UNIX OFF)
    set(ATHDNS_BUILD_ON_WINDOWS "Build ON Windows" ON)
  endif()
endif()

include(Fmt)
include(CompilerOptionCheck)
include(ConfigCheck)
include(FindLibuv)
include(FindJemalloc)
include(TestBigEndian)

add_library(coverage_config INTERFACE)

option(ATHDNS_ENABLE_CODE_COVERAGE "Enable coverage reporting" OFF)

if(${ATHDNS_ENABLE_CODE_COVERAGE})
  message(STATUS "Enable Code Coverage")
  include(CodeCoverage)
  append_coverage_compiler_flags()
endif()

if(${CMAKE_CXX_COMPILER_ID} STREQUAL Clang)
  add_definitions(-Wno-undef)
  add_definitions(-Wno-unused-macros)
endif()

test_big_endian(ON_BIG_ENDIAN)

include_directories(${ATHDNS_INCLUDE_ROOT})

aux_source_directory(dns ATHDNS_DRIVER_LIB_LIST)
aux_source_directory(server ATHDNS_DRIVER_LIB_LIST)

list(REMOVE_ITEM ATHDNS_DRIVER_LIB_LIST "server/main.cpp")

include(FindFLEX)
include(FindBISON)

find_package(FLEX)
find_package(BISON)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps/config_parser)

bison_target(ConfigParser ${CMAKE_SOURCE_DIR}/server/config_file.y
  ${CMAKE_CURRENT_BINARY_DIR}/deps/config_parser/bison_parser.c)
flex_target(ConfigLexer ${CMAKE_SOURCE_DIR}/server/config_file.l
  ${CMAKE_CURRENT_BINARY_DIR}/deps/config_parser/flex_lexer.c)

include_directories(${CMAKE_CURRENT_BINARY_DIR}/deps/config_parser ${LIBUV_INCLUDE_DIR})

add_flex_bison_dependency(ConfigLexer ConfigParser)

list(APPEND ATHDNS_LIB_SOURCE_LIST
  ${CMAKE_CURRENT_BINARY_DIR}/deps/config_parser/flex_lexer.c
  ${CMAKE_CURRENT_BINARY_DIR}/deps/config_parser/bison_parser.c)

add_library(utils STATIC ${ATHDNS_LIB_SOURCE_LIST} ${ATHDNS_DRIVER_LIB_LIST})

add_dependencies(utils fmt)

add_executable(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/server/main.cpp)

set(ATHDNS_LIBS ${ATHDNS_LIBS} utils)

list(APPEND ATHDNS_LIBS libfmt)

if(${JEMALLOC_FOUND})
  set(HAVE_JEMALLOC ON)
  include_directories(${JEMALLOC_INCLUDE_DIR})
  list(APPEND ATHDNS_LIBS jemalloc)
  add_definitions(-fno-builtin-malloc)
  add_definitions(-fno-builtin-free)
  add_definitions(-fno-builtin-calloc)
  add_definitions(-fno-builtin-realloc)
endif()

configure_file(${ATHDNS_INCLUDE_ROOT}/config.h.in
  ${ATHDNS_INCLUDE_ROOT}/config.h)

add_definitions(-DHAVE_CONFIG_H)

target_link_libraries(${PROJECT_NAME} ${LIBUV_LIBRARIES} ${ATHDNS_LIBS} pthread)

if (${ATHDNS_ENABLE_TESTING})
  enable_testing()
  add_subdirectory(${CMAKE_SOURCE_DIR}/tests)
endif()
