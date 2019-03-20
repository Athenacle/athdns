#!/bin/bash

mkdir -p build

export VERBOSE=1

pushd build || exit 1

cmake .. -DCMAKE_BUILD_TYPE=Release -DATHDNS_ENABLE_TESTING=ON -DATHDNS_ENABLE_CODE_COVERAGE=OFF -DATHDNS_ENABLE_DOH=ON -DATHDNS_USE_OPENSSL=ON

cmake --build . --config Debug || exit 1

bin/dnstest || exit 1

popd || exit 1

rm -rf build/

mkdir -p build

pushd build || exit 1

cmake .. -DCMAKE_BUILD_TYPE=Debug -DATHDNS_ENABLE_TESTING=ON -DATHDNS_ENABLE_CODE_COVERAGE=ON -DATHDNS_ENABLE_DOH=ON -DATHDNS_USE_MBEDTLS=OFF -DATHDNS_USE_OPENSSL=ON

cmake --build . --config Debug || exit 1

bin/dnstest || exit 1

cmake --build . --config Debug --target dnstest_coverage || exit 1
