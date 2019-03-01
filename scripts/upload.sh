#!/bin/sh


cur=$(pwd)/build

cd "$cur" || exit -1

lcov --remove dnstest_coverage.info "$cur""/*" "/usr/*" --output-file coverage.info

lcov --list coverage.info

curl https://codecov.io/bash -o codecov.bash

bash codecov.bash -f coverage.info -t "$CODECOV_TOKEN"
