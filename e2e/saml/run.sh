#!/usr/bin/env bash
# Copyright 2026 Hyperscale. All rights reserved.
# Use of this source code is governed by a MIT
# license that can be found in the LICENSE file.
#
# Opt-in browser suite of the SAML Service Provider (`make e2e`), never run
# by `make test` or CI. It needs Tales and Chrome (docs/saml-sp.md, "Testing
# your integration"), and the ports 8084, 18443 and 18480 free on loopback.
#
# It builds examples/saml-sp and the helper process (TestE2EHelperProcess in
# internal/interop/saml), starts the helper, which starts the example behind
# the TLS sites, runs `tales test e2e/saml`, and stops everything. Extra
# arguments go to `tales test` (for instance --scenario "<name>"). Set
# SAMLSP_E2E_KEEP to a directory to keep the example's and the helper's logs.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tales="${TALES:-tales}"
work="$(mktemp -d "${TMPDIR:-/tmp}/samlsp-e2e.XXXXXX")"
helper=""

cleanup() {
    if [ -n "$helper" ] && kill -0 "$helper" 2>/dev/null; then
        kill -TERM "$helper" 2>/dev/null || true
        wait "$helper" 2>/dev/null || true
    fi

    if [ -n "${SAMLSP_E2E_KEEP:-}" ]; then
        mkdir -p "$SAMLSP_E2E_KEEP"
        cp "$work"/*.log "$SAMLSP_E2E_KEEP"/ 2>/dev/null || true
    fi

    rm -rf "$work"
}
trap cleanup EXIT

if ! command -v "$tales" >/dev/null 2>&1; then
    echo "tales not found (set TALES or install it, see docs/saml-sp.md)" >&2
    exit 2
fi

(cd "$root/examples" && go build -o "$work/saml-sp" ./saml-sp)
(cd "$root/internal/interop/saml" && go test -c -o "$work/interop.test" .)

SAMLSP_E2E_SERVE="$work/ready" SAMLSP_E2E_EXAMPLE="$work/saml-sp" SAMLSP_E2E_EXAMPLE_LOG="$work/saml-sp.log" \
    "$work/interop.test" -test.run '^TestE2EHelperProcess$' -test.timeout 0 -test.v >"$work/helper.log" 2>&1 &
helper=$!

for _ in $(seq 1 300); do
    if [ -s "$work/ready" ]; then
        break
    fi

    if ! kill -0 "$helper" 2>/dev/null; then
        cat "$work/helper.log" >&2
        exit 1
    fi

    sleep 0.1
done

if [ ! -s "$work/ready" ]; then
    echo "the helper did not start" >&2
    cat "$work/helper.log" >&2
    exit 1
fi

# The runtime certificate's SPKI hashes, for Chrome.
# shellcheck disable=SC1091
. "$work/ready"
export SAMLSP_E2E_SPKI

cd "$root"
"$tales" validate e2e/saml
"$tales" test e2e/saml --seed 1234 --timeout 5m --parallel 1 "$@"
