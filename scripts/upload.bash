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

cat >> package.json << EOF
{
  "dependencies": {
    "codacy-coverage": "^3.4.0"
  }
}
EOF

npm install

SHA=$(git rev-parse HEAD)

node node_modules/codacy-coverage/bin/codacy-coverage.js < "$build_dir"/coverage.info \
     -t "$CODACY_PROJECT_TOKEN" \
     -a "$CODACY_API_TOKEN" \
     -u "Athenacle" \
     -c "$SHA" \
     -l "CPP" \
     -p "$root" \
     -n "athdns"
