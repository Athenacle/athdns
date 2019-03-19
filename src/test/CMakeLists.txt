
include(Gtest)

set(ATHDNS_GTEST_BIN_NAME dnstest)

if (${ATHDNS_ENABLE_CODE_COVERAGE})
  include(CodeCoverage)

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

add_executable(${ATHDNS_GTEST_BIN_NAME}
  ${ATHDNS_TEST_DIR}/tests.cpp
  ${ATHDNS_TEST_DIR}/dns_test.cpp
  ${ATHDNS_TEST_DIR}/utils_test.cpp
  ${ATHDNS_TEST_DIR}/hash_test.cpp
  ${ATHDNS_TEST_DIR}/server_test.cpp
  ${ATHDNS_TEST_DIR}/dns_record_test.cpp)

add_dependencies(${ATHDNS_GTEST_BIN_NAME} gtest)

target_link_libraries(${ATHDNS_GTEST_BIN_NAME} libgtest ${ATHDNS_LIBS} ${LIBUV_LIBRARIES})

if(${ATHDNS_ENABLE_DOH})
  target_link_libraries(${ATHDNS_GTEST_BIN_NAME} ${NGHTTP2_LIBRARY} ${SSL_LIB})
endif()
