#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Docker CLI stub used by integration tests. It records each argv item on its
# own line and writes a deterministic container id to the --cidfile path.

set -eu

: "${APOLYSIS_DOCKER_STUB_LOG:?missing APOLYSIS_DOCKER_STUB_LOG}"

printf '%s\n' "$@" > "$APOLYSIS_DOCKER_STUB_LOG"

cidfile=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "--cidfile" ]; then
    cidfile="$arg"
    break
  fi
  previous="$arg"
done

if [ -n "$cidfile" ]; then
  mkdir -p "$(dirname "$cidfile")"
  printf '%s\n' "${APOLYSIS_DOCKER_STUB_CID:-apolysis-stub-container}" > "$cidfile"
fi

exit "${APOLYSIS_DOCKER_STUB_EXIT:-0}"
