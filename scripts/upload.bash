#!/bin/bash

root=$(pwd)
build_dir="$root"/build

pushd "$build_dir" || exit -1

lcov --remove dnstest_coverage.info "$build_dir""/*" "/usr/*" --output-file coverage.info

lcov --list coverage.info

curl -s -L https://codecov.io/bash -o codecov.bash

bash codecov.bash -f coverage.info -t "$CODECOV_TOKEN"

codacy_dir="$build_dir"/codacy

mkdir -p "$codacy_dir"

pushd "$codacy_dir" || exit -1

curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ rc main" | sudo tee /etc/apt/sources.list.d/yarn.list

sudo apt-get update -q
sudo apt-get install --no-install-recommends -y yarn

SHA=$(git rev-parse HEAD)

yarn add codacy-coverage

yarn codacy-coverage < "$build_dir"/coverage.info \
     -t "$CODACY_PROJECT_TOKEN" \
     -a "$CODACY_API_TOKEN" \
     -u "Athenacle" \
     -c "$SHA" \
     -l "CPP" \
     -p "$root" \
     -n "athdns"
