
include(Gtest)

include(CodeCoverage)

append_coverage_compiler_flags()

setup_target_for_coverage_lcov(
  NAME dnstest_coverage
  EXECUTABLE dnstest
  DEPENDENCIES dnstest)

include_directories(${CMAKE_SOURCE_DIR}/test)

if(${CMAKE_CXX_COMPILER_ID} STREQUAL Clang)
  add_definitions(-Wno-c++98-compat)
  add_definitions(-Wno-c++98-compat-pedantic)
  add_definitions(-Wno-c++98-compat-extra-semi)
  add_definitions(-Wno-weak-vtables)
  add_definitions(-Wno-global-constructors)
endif()

add_executable(dnstest
  ${CMAKE_SOURCE_DIR}/tests/test_dns.cpp
  ${CMAKE_SOURCE_DIR}/tests/utils.cpp
  ${CMAKE_SOURCE_DIR}/tests/test_utils.cpp
  ${CMAKE_SOURCE_DIR}/tests/hash_test.cpp
  ${CMAKE_SOURCE_DIR}/tests/dns_record.cpp
  ${CMAKE_SOURCE_DIR}/tests/main.cpp)

add_dependencies(dnstest gtest)

target_link_libraries(dnstest libgtest ${ATHDNS_LIBS} ${LIBUV_LIBRARIES})

