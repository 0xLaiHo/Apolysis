#!/usr/bin/env bash

set -Eeuo pipefail

readonly script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

export APOLYSIS_GATEWAY_MIXED_LIFECYCLE_DEADLINE_RACES=1
export APOLYSIS_GATEWAY_TRANSPORT_TEST_TIMEOUT_SECONDS="${APOLYSIS_GATEWAY_MIXED_LIFECYCLE_DEADLINE_RACES_TEST_TIMEOUT_SECONDS:-1200}"

exec "${script_directory}/test-gateway-transport-mtls.sh" "$@"
