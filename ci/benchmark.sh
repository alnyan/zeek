#! /usr/bin/env bash

set -e

# Don't do this for any branch that isn't from the main zeek repo.
# TODO: is it possible to do this from cirrus.yml instead of here?
if [ "${CIRRUS_REPO_OWNER}" != "zeek" ]; then
    exit 0
fi

BUILD_URL="https://api.cirrus-ci.com/v1/artifact/build/${CIRRUS_BUILD_ID}/${CIRRUS_TASK_NAME}/upload_binary/build.tgz"

# Generate an md5 hash of the build file. We can do this here because the path to the
# file still exists from the prior scripts.
BUILD_HASH=$(md5sum build.tgz)

# Generate an HMAC digest for the path plus a timestamp to send as an authentication
# header. Openssl outputs a hex string here so there's no need to base64 encode it.
# TODO: would it make sense to add the build hash as part of the hmac key here just
# for more uniqueness?
TIMESTAMP=$(date +'%s')
HMAC_DIGEST=$(echo "/zeek${TIMESTAMP}" | openssl dgst -sha256 -hmac ${ZEEK_BENCHMARK_HMAC_KEY} | awk '{print $2}')

# Make a request to the benchmark host.
curl -X POST -H "Zeek-HMAC: ${HMAC_DIGEST}" -H "Zeek-HMAC-Timestamp: ${TIMESTAMP}" \"${ZEEK_BENCHMARK_ENDPOINT}?branch=${CIRRUS_BRANCH}\&build=${BUILD_URL}\&build_hash=${BUILD_HASH}\"
