#!/usr/bin/env bash

set -Eeuo pipefail

export APOLYSIS_GATEWAY_MULTIPROCESS_LIFECYCLE_RACES=1
export APOLYSIS_GATEWAY_TRANSPORT_TEST_TIMEOUT_SECONDS="${APOLYSIS_GATEWAY_TRANSPORT_TEST_TIMEOUT_SECONDS:-1200}"

exec "$(dirname "$0")/test-gateway-transport-mtls.sh" "$@"
