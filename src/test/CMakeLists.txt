
include(Gtest)

if (${ATHDNS_ENABLE_CODE_COVERAGE})
  include(CodeCoverage)

  append_coverage_compiler_flags()

  setup_target_for_coverage_lcov(
    NAME dnstest_coverage
    EXECUTABLE dnstest
    DEPENDENCIES dnstest)
endif()

include_directories(${CMAKE_SOURCE_DIR}/test)

if(${CMAKE_CXX_COMPILER_ID} STREQUAL Clang)
  add_definitions(-Wno-c++98-compat)
  add_definitions(-Wno-c++98-compat-pedantic)
  add_definitions(-Wno-c++98-compat-extra-semi)
  add_definitions(-Wno-weak-vtables)
  add_definitions(-Wno-global-constructors)
endif()

set(ATHDNS_TEST_DIR ${CMAKE_SOURCE_DIR}/src/test)

add_executable(dnstest
  ${ATHDNS_TEST_DIR}/test_dns.cpp
  ${ATHDNS_TEST_DIR}/utils.cpp
  ${ATHDNS_TEST_DIR}/test_utils.cpp
  ${ATHDNS_TEST_DIR}/hash_test.cpp
  ${ATHDNS_TEST_DIR}/dns_record.cpp
  ${ATHDNS_TEST_DIR}/main.cpp)

add_dependencies(dnstest gtest)

target_link_libraries(dnstest libgtest ${ATHDNS_LIBS} ${LIBUV_LIBRARIES})

