#!/bin/sh

mkdir -p build && cd build

cmake .. -DCMAKE_BUILD_TYPE=Debug -DATHDNS_ENABLE_TESTING=ON -DATHDNS_ENABLE_CODE_COVERAGE=ON

cmake --build . --config Debug

tests/dnstest

cmake --build . --config Debug --target dnstest_coverage
