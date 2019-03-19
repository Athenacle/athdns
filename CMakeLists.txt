
cmake_minimum_required(VERSION 3.4)

project(athdns C CXX)

option(ATHDNS_ENABLE_TESTING "Enable Testing" OFF)
option(ATHDNS_ENABLE_CODE_COVERAGE "Enable coverage reporting" OFF)
option(ATHDNS_ENABLE_DOH "Enable DoH (DNS over Https)" ON)
option(ATHDNS_USE_OPENSSL "Prefer OpenSSL as crypto library" ON)
option(ATHDNS_USE_MBEDTLS "Prefer MBEDTLS as crypto library" OFF)
option(ATHDNS_USE_JEMALLOC "Use jemalloc for malloc(3)" ON)



if (${ATHDNS_ENABLE_DOH})
  if (${ATHDNS_USE_OPENSSL} AND ${ATHDNS_USE_MBEDTLS})
    message(STATUS "ATHDNS_USE_OPENSSL and ATHDNS_USE_MBEDTLS cannot be both set. Use OpenSSL.")
    set(ATHDNS_USE_MBEDTLS OFF)
  endif()

  if (NOT ${ATHDNS_USE_OPENSSL} AND NOT ${ATHDNS_USE_MBEDTLS})
    message(STATUS "ATHDNS_USE_OPENSSL and ATHDNS_USE_MBEDTLS cannot be both unset. Use OpenSSL.")
    set(ATHDNS_USE_OPENSSL ON)
  endif()
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)
set(ATHDNS_INCLUDE_ROOT ${CMAKE_SOURCE_DIR}/include/)
set(ATHDNS_DEPS_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps)
set(THIRD_PARTY_DIR ${ATHDNS_DEPS_DIR}/third_party)

file(MAKE_DIRECTORY ${ATHDNS_DEPS_DIR})
file(MAKE_DIRECTORY ${THIRD_PARTY_DIR})

set(CMAKE_CXX_STANDARD 14)
set(PROJECT_NAME athdns)
set(PROJECT_VERSION 0.0.0)

string(TIMESTAMP ATHDNS_BUILD_TIME "%Y-%m-%d %H:%M:%SZ")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(UNIX)
  set(ON_UNIX "Build ON UNIX" ON)
  set(ATHDNS_BUILD_ON_WINDOWS OFF)
else()
  if(WINDOWS)
    set(ATHDNS_BUILD_ON_UNIX OFF)
    set(ON_WINDOWS "Build ON Windows" ON)
  endif()
endif()

include(ThirdParty)
include(CheckCXXCompilerFlag)
include(ConfigCheck)
include(FindLibuv)
include(TestBigEndian)

set(SSL_LIB)

if(${ATHDNS_ENABLE_DOH})
  set(HAVE_DOH_SUPPORT ON)
  include(FindNgHttp2)
  include_directories(${NGHTTP2_INCLUDE_DIR})
  if (${ATHDNS_USE_OPENSSL})
    include(FindOpenSSL)
    if (NOT ${OpenSSL_FOUND})
      message(FATAL_ERROR "OpenSSL not found.")
    else()
      set(HAVE_OPENSSL ON)
      include_directories(${OPENSSL_INCLUDE_DIR})
      list(APPEND SSL_LIB ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
    endif()
  else()
    if (${ATHDNS_USE_MBEDTLS})
      include(FindMbedTLS)
      if (NOT ${MBEDTLS_FOUND})
        message(FATAL_ERROR "MbedTLS not found.")
      else()
        set(HAVE_MBEDTLS ON)
        include_directories(${MBEDTLS_INCLUDE_DIRS})
        list(APPEND SSL_LIB ${MBEDCRYPTO_LIBRARY} ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY})
      endif()
    else()
      message(FATAL_ERROR "No OpenSSL or MbedTLS specified.")
    endif()
  endif()
endif()

if(${ATHDNS_ENABLE_CODE_COVERAGE})
  add_library(coverage_config INTERFACE)
  message(STATUS "Enable Code Coverage")
  include(CodeCoverage)
  append_coverage_compiler_flags()
endif()


if ((${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang") OR
    ${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")

  macro(CXX_COMPILER_CHECK_ADD)
    set(list_var "${ARGN}")
    foreach(flag IN LISTS list_var)
      string(TOUPPER ${flag} FLAG_NAME1)
      string(REPLACE "-" "_" FLAG_NAME2 ${FLAG_NAME1})
      string(CONCAT FLAG_NAME "COMPILER_SUPPORT_" ${FLAG_NAME2})
      check_cxx_compiler_flag(-${flag} ${FLAG_NAME})
      if (${${FLAG_NAME}})
        add_compile_options(-${flag})
      endif()
    endforeach()
  endmacro()

  CXX_COMPILER_CHECK_ADD(Wall
    Wextra
    Wpedantic
    Wduplicated-branches
    Wduplicated-cond
    Wlogical-op
    Wrestrict
    Wnull-dereference
    Wuseless-cast)

  check_cxx_compiler_flag(-fno-permissive COMPILER_SUPPORT_FNOPERMISSIVE)

  if (${COMPILER_SUPPORT_FNOPERMISSIVE})
    set(CMAKE_CXX_FLAGS "-fno-permissive ${CMAKE_CXX_FLAGS}")
  endif()

endif()

test_big_endian(ON_BIG_ENDIAN)

include_directories(${ATHDNS_INCLUDE_ROOT})

set(ATHDNS_LIB_SRC
  src/config.cpp
  src/dns.cpp
  src/hash.cpp
  src/logging.cpp
  src/record.cpp
  src/server.cpp
  src/objects.cpp
  src/remote.cpp
  src/uvcb.cpp
  src/utils.cpp)

if(${ATHDNS_ENABLE_DOH})
  list(APPEND ATHDNS_LIB_SRC
    src/doh.cpp
    src/ssl.cpp)
endif()

include(FindFLEX)
include(FindBISON)

find_package(FLEX)
find_package(BISON)

set(ATHDNS_PARSER_DIR ${CMAKE_SOURCE_DIR}/src/parser)
set(ATHDNS_PARSER_RESULT_DIR ${ATHDNS_DEPS_DIR}/config_parser)

file(MAKE_DIRECTORY ${ATHDNS_PARSER_RESULT_DIR})

bison_target(ConfigParser ${ATHDNS_PARSER_DIR}/config_file.y
  ${ATHDNS_PARSER_RESULT_DIR}/bison_parser.c)
flex_target(ConfigLexer ${ATHDNS_PARSER_DIR}/config_file.l
  ${ATHDNS_PARSER_RESULT_DIR}/flex_lexer.c)

include_directories(${LIBUV_INCLUDE_DIR})

add_flex_bison_dependency(ConfigLexer ConfigParser)

set_source_files_properties(${ATHDNS_PARSER_RESULT_DIR}/flex_lexer.c
  PROPERTIES COMPILE_FLAGS -I${ATHDNS_PARSER_RESULT_DIR})
set_source_files_properties(${ATHDNS_PARSER_RESULT_DIR}/bison_parser.c
  PROPERTIES COMPILE_FLAGS -I${ATHDNS_PARSER_RESULT_DIR})

add_library(utils STATIC
  ${ATHDNS_LIB_SRC}
  ${ATHDNS_PARSER_RESULT_DIR}/flex_lexer.c
  ${ATHDNS_PARSER_RESULT_DIR}/bison_parser.c)

set(ATHDNS_BIN_DIR ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${ATHDNS_BIN_DIR})
file(MAKE_DIRECTORY ${ATHDNS_BIN_DIR})

set(ATHDNS_BIN_NAME ${ATHDNS_BIN_DIR}/${PROJECT_NAME})

add_dependencies(utils 3party)

add_executable(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/src/main.cpp)

set(ATHDNS_LIBS ${ATHDNS_LIBS} utils ${THIRD_PARTY_LIBRARIES})

if (${ATHDNS_USE_JEMALLOC})
  include(FindJemalloc)
  if(${JEMALLOC_FOUND})
    set(HAVE_JEMALLOC ON)
    include_directories(${JEMALLOC_INCLUDE_DIR})
    list(APPEND ATHDNS_LIBS jemalloc)
    add_definitions(-fno-builtin-malloc)
    add_definitions(-fno-builtin-free)
    add_definitions(-fno-builtin-calloc)
    add_definitions(-fno-builtin-realloc)
  else()
    message(WARNING "jemalloc NOT found. Turn ATHDNS_USE_JEMALLOC OFF")
    set(ATHDNS_USE_JEMALLOC OFF)
    set(HAVE_JEMALLOC OFF)
  endif()
endif()

set(ATHDNS_BUILD_SHA "unknown")

find_program(GIT_BIN git)

if (GIT_BIN)
  execute_process(
    COMMAND ${GIT_BIN} rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE ATHDNS_BUILD_SHA
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

configure_file(${ATHDNS_INCLUDE_ROOT}/config.h.in
  ${ATHDNS_INCLUDE_ROOT}/config.h)

add_definitions(-DHAVE_CONFIG_H)

target_link_libraries(${PROJECT_NAME} ${ATHDNS_LIBS})
target_link_libraries(${PROJECT_NAME} ${LIBUV_LIBRARIES})

if (${ATHDNS_ENABLE_DOH})
  target_link_libraries(${PROJECT_NAME} ${NGHTTP2_LIBRARY} ${SSL_LIB})
endif()

target_link_libraries(${PROJECT_NAME} pthread)

if (${ATHDNS_ENABLE_TESTING})
  enable_testing()
  add_subdirectory(${CMAKE_SOURCE_DIR}/src/test)
endif()
