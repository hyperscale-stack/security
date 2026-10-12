#!/bin/sh
# Copyright 2026 Hyperscale. All rights reserved.
# Use of this source code is governed by a MIT
# license that can be found in the LICENSE file.
#
# Runs the OpenID Foundation conformance suite locally against this
# repository's OpenID Connect stack — opt-in, never part of `make test` or
# CI, and not an OpenID Certification:
#
#   - OP plans (scripts/run-test-plan.py of the suite) against oidc/provider,
#     served by TestConformanceOPHelperProcess at
#     https://host.docker.internal:$OIDC_CONFORMANCE_OP_PORT under
#     oauth2.Profile20 with a headless Interaction;
#   - RP plans against oidc/client, driven by TestConformanceRPPlans through
#     the suite's REST API.
#
# Prerequisites: Docker (compose v2.24 or later), Go, Python 3, openssl,
# curl, and a checkout of the suite at commit 11999aad with its prebuilt
# images pulled:
#
#   git clone https://gitlab.com/openid/conformance-suite.git
#   git -C conformance-suite checkout 11999aad
#   docker compose -f conformance-suite/docker-compose-prebuilt.yml pull
#   OIDF_SUITE_DIR=$PWD/conformance-suite make conformance
#
# Ports 8443 and 8444 (the suite) and $OIDC_CONFORMANCE_OP_PORT (9443) must
# be free. OIDC_CONFORMANCE_PLANS selects "op", "rp" or both (default).
# Everything the run produces lands in build/conformance: TLS material,
# plan configurations, exports, results and summary.md. Expect 30 to 60
# minutes.
set -eu

root=$(cd "$(dirname "$0")/../../../.." && pwd)
module=$root/internal/interop/oidcstack
package=$module/conformance
out=$root/build/conformance
suite_commit=11999aad
op_port=${OIDC_CONFORMANCE_OP_PORT:-9443}
plans=${OIDC_CONFORMANCE_PLANS:-op rp}
suite_url=https://localhost.emobix.co.uk:8443/
project=oidc-conformance

: "${OIDF_SUITE_DIR:?set OIDF_SUITE_DIR to a checkout of the conformance suite (see $0)}"

for tool in docker go python3 openssl curl git; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "conformance: $tool is required (see the header of $0)" >&2
		exit 1
	}
done

head=$(git -C "$OIDF_SUITE_DIR" rev-parse --short=8 HEAD)
case $head in
"$suite_commit"*) ;;
*) echo "conformance: warning: the suite checkout is at $head, the recorded runs at $suite_commit" >&2 ;;
esac

# The provider listens where the suite's containers reach the host: the
# loopback interface with Docker Desktop, the default bridge's gateway on
# Linux (never every interface).
if [ "$(uname -s)" = Linux ]; then
	op_host=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
else
	op_host=127.0.0.1
fi

rm -rf "$out"
mkdir -p "$out/tls" "$out/op" "$out/rp"

# TLS: a CA of the run, the suite's nginx certificate, the provider's.
tls=$out/tls
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=conformance run CA" \
	-keyout "$tls/ca.key" -out "$tls/ca.crt" 2>/dev/null

issue() { # name subjectAltName
	openssl req -newkey rsa:2048 -nodes -subj "/CN=$1" -keyout "$tls/$1.key" -out "$tls/$1.csr" 2>/dev/null
	printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$2" >"$tls/$1.ext"
	openssl x509 -req -in "$tls/$1.csr" -CA "$tls/ca.crt" -CAkey "$tls/ca.key" -CAcreateserial \
		-days 2 -extfile "$tls/$1.ext" -out "$tls/$1.crt" 2>/dev/null
}

issue nginx "DNS:localhost.emobix.co.uk,DNS:localhost"
issue op "DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1,IP:$op_host"
chmod 0644 "$tls/nginx.key"

compose() {
	CONFORMANCE_TLS_DIR=$tls docker compose -p "$project" \
		-f "$OIDF_SUITE_DIR/docker-compose-prebuilt.yml" -f "$package/compose.override.yml" "$@"
}

op_pid=

# shellcheck disable=SC2329 # invoked by the trap
cleanup() {
	if [ -n "$op_pid" ]; then
		kill "$op_pid" 2>/dev/null || true
		wait "$op_pid" 2>/dev/null || true
	fi

	compose down --volumes >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

compose up -d

echo "conformance: waiting for the suite at $suite_url"
i=0
until curl -fsS --cacert "$tls/ca.crt" -o /dev/null "${suite_url}api/plan?length=1" 2>/dev/null; do
	i=$((i + 1))
	if [ "$i" -gt 120 ]; then
		echo "conformance: the suite did not come up (docker compose -p $project logs)" >&2
		exit 1
	fi
	sleep 3
done

curl -fsS --cacert "$tls/ca.crt" "${suite_url}api/server" >"$out/suite-server.json"

(cd "$module" && go test -c -o "$out/conformance.test" ./conformance)

status=0

case " $plans " in
*" op "*)
	OIDC_CONFORMANCE_OP_READY=$out/op/ready.json \
		OIDC_CONFORMANCE_OP_ADDR=$op_host:$op_port \
		OIDC_CONFORMANCE_OP_ISSUER=https://host.docker.internal:$op_port \
		OIDC_CONFORMANCE_OP_CERT=$tls/op.crt OIDC_CONFORMANCE_OP_KEY=$tls/op.key \
		OIDC_CONFORMANCE_OP_CALLBACK=${suite_url}test/a/hyperscale-op/callback \
		sh -c 'cd "$1" && exec "$2" -test.run "^TestConformanceOPHelperProcess\$" -test.timeout 0 -test.v' \
		op-helper "$package" "$out/conformance.test" >"$out/op/helper.log" 2>&1 &
	op_pid=$!

	i=0
	until [ -s "$out/op/ready.json" ]; do
		i=$((i + 1))
		if [ "$i" -gt 100 ]; then
			echo "conformance: the provider did not start ($out/op/helper.log)" >&2
			exit 1
		fi
		sleep 0.3
	done

	python3 -m venv "$out/venv"
	"$out/venv/bin/pip" install --quiet httpx==0.28.1 pyparsing==3.2.3
	"$out/venv/bin/pip" freeze >"$out/venv-freeze.txt"

	(
		cd "$out/op"
		PYTHONDONTWRITEBYTECODE=1 CONFORMANCE_DEV_MODE=1 \
			CONFORMANCE_SERVER=$suite_url CONFORMANCE_SERVER_MTLS=https://localhost.emobix.co.uk:8444/ \
			"$out/venv/bin/python" -B "$OIDF_SUITE_DIR/scripts/run-test-plan.py" \
			--export-dir "$out/op" --verbose \
			--expected-failures-file "$package/testdata/op-expected-failures.json" \
			--expected-skips-file "$package/testdata/op-expected-skips.json" \
			"oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" "$out/op/op-config.json" \
			"oidcc-config-certification-test-plan" "$out/op/op-config.json" \
			"oidcc-config-certification-test-plan" "$out/op/op-config-tenant.json"
	) >"$out/op/run-test-plan.log" 2>&1 || status=1

	tail -n 60 "$out/op/run-test-plan.log"
	;;
esac

case " $plans " in
*" rp "*)
	(cd "$package" && OIDC_CONFORMANCE_RP=1 CONFORMANCE_SERVER=$suite_url \
		OIDC_CONFORMANCE_CA=$tls/ca.crt OIDC_CONFORMANCE_RP_OUT=$out/rp \
		"$out/conformance.test" -test.run '^TestConformanceRPPlans$' -test.timeout 0 -test.v) \
		>"$out/rp/driver.log" 2>&1 || status=1

	grep -E '^\s+rp_test.go:[0-9]+: |^(--- |ok|FAIL|PASS)' "$out/rp/driver.log" | tail -n 120
	;;
esac

{
	echo "# OpenID conformance suite — local run (not an OpenID Certification)"
	echo
	echo "- date: $(date -u +%Y-%m-%dT%H:%MZ)"
	echo "- repository: $(git -C "$root" rev-parse HEAD)"
	echo "- suite checkout: $(git -C "$OIDF_SUITE_DIR" rev-parse HEAD)"
	echo "- suite server: $(cat "$out/suite-server.json")"
	echo "- images (pinned by compose.override.yml):"
	grep 'image:' "$package/compose.override.yml" | sed 's/^ *image: */  - /'
	echo "- python: $(python3 --version 2>&1), venv: $(tr '\n' ' ' <"$out/venv-freeze.txt" 2>/dev/null)"
	echo "- go: $(go version), docker: $(docker version --format '{{.Server.Version}}'), os: $(uname -srm)"
	echo "- plans: $plans; exit status: $status"
} >"$out/summary.md"

echo "conformance: done (status $status) — $out/summary.md"
exit "$status"
