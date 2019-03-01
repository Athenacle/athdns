#!/bin/sh


cur=$(pwd)/build

cd "$cur" || exit -1

lcov --remove dnstest_coverage.info '"$cur"/*' '/usr/*' --output-file coverage.info

lcov --list coverage.info

bash < (curl -s https://codecov.io/bash) -f coverage.info -t $CODECOV_TOKEN || echo "Codecov did not collect coverage reports"
