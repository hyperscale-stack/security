#!/bin/sh
# Copyright 2026 Hyperscale. All rights reserved.
# Use of this source code is governed by a MIT
# license that can be found in the LICENSE file.
#
# Runs the Tales end-to-end suite of the OpenID Connect examples: builds
# examples/oidc-provider and examples/oidc-client, starts them on the
# loopback interface — the provider at http://localhost:8083, the relying
# party at http://127.0.0.1:9000, two sites for the browser; the redirect
# URI is a loopback IP literal, the only http one the provider's
# Profile20BCP accepts (RFC 9700 §2.6) — and runs the scenarios. Opt-in,
# never part of `make test` or CI.
#
# Prerequisites: Go, curl, openssl, Chrome (or CHROME_PATH) and Tales
# v0.1.0-rc.23:
#
#   go install github.com/tales-testing/tales/cmd/tales@d50dd8bdfae9886996fa280072a698df0c0f24ad
#
# Phases: the provider scenarios run in parallel against one pair of
# servers; each relying-party and browser file then runs alone on fresh
# servers, because it relies on a first consent and on the relying party's
# account numbering. Reports, logs and artifacts: build/e2e-oidc.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
suite=$root/e2e/oidc
out=$root/build/e2e-oidc
op_port=${OIDC_E2E_OP_PORT:-8083}
rp_port=${OIDC_E2E_RP_PORT:-9000}
issuer=http://localhost:$op_port
rp_url=http://127.0.0.1:$rp_port

for tool in go curl openssl tales; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "e2e-oidc: $tool is required (see the header of $0)" >&2
		exit 1
	}
done

mkdir -p "$out/bin"
(cd "$root/examples" && go build -o "$out/bin/" ./oidc-provider ./oidc-client)

op_pid=
rp_pid=

stop() {
	for pid in $op_pid $rp_pid; do
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done

	op_pid=
	rp_pid=
}

trap stop EXIT INT TERM

# wait_for URL: polls URL until it answers, for at most 10 s.
wait_for() {
	i=0
	until curl -fsS -o /dev/null "$1" 2>/dev/null; do
		i=$((i + 1))
		if [ "$i" -gt 50 ]; then
			echo "e2e-oidc: $1 did not come up (logs in $out)" >&2
			exit 1
		fi
		sleep 0.2
	done
}

# start launches fresh servers: in-memory state, new keys.
start() {
	OIDC_PROVIDER_ISSUER=$issuer OIDC_PROVIDER_ADDR=localhost:$op_port \
		OIDC_PROVIDER_REDIRECT_URI=$rp_url/oidc/demo/callback \
		"$out/bin/oidc-provider" >>"$out/oidc-provider.log" 2>&1 &
	op_pid=$!
	wait_for "$issuer/.well-known/openid-configuration"

	BASE_URL=$rp_url ADDR=127.0.0.1:$rp_port OIDC_DEV_ALLOW_LOOPBACK=1 \
		OIDC_CONNECTIONS=demo OIDC_DEMO_ISSUER=$issuer \
		OIDC_DEMO_CLIENT_ID=demo-rp OIDC_DEMO_CLIENT_SECRET=demo-rp-secret \
		OIDC_TRANSACTION_KEYS=$(openssl rand -hex 32) \
		"$out/bin/oidc-client" >>"$out/oidc-client.log" 2>&1 &
	rp_pid=$!
	wait_for "$rp_url/"
}

# Tales writes its artifacts (screenshots, DOM snapshots) under the working
# directory: keep them in the build directory.
cd "$out"

export OIDC_E2E_ISSUER="$issuer"
export OIDC_E2E_RP_URL="$rp_url"
export OIDC_E2E_REDIRECT_URI="$rp_url/oidc/demo/callback"

tales validate "$suite"

status=0

start
tales test "$suite" --tag provider --seed 1234 --timeout 10m \
	--report-junit "$out/provider.xml" || status=1
stop

for tag in rp-callback browser-lifecycle browser-cross-site; do
	start
	tales test "$suite" --tag "$tag" --parallel 1 --seed 1234 --timeout 10m \
		--report-junit "$out/$tag.xml" || status=1
	stop
done

exit "$status"
