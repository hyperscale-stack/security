#!/bin/sh
# Copyright 2026 Hyperscale. All rights reserved.
# Use of this source code is governed by a MIT
# license that can be found in the LICENSE file.
#
# Runs the store suites on real servers, with the race detector
# (`make test-backends`; in CI, the "Store suites (real backends)" job of
# .github/workflows/go.yml, against service containers):
#
#   internal/interop/sqlstores   the three SQL stores on PostgreSQL, MySQL
#                                8.0 and 8.4, MariaDB (and SQLite)
#   internal/interop/oidcstack   the OIDC client stores on PostgreSQL,
#                                MySQL and Redis (the root package)
#   internal/interop/saml        the SAML stores on PostgreSQL, MySQL and
#                                Redis (the whole package but its Keycloak
#                                and browser-helper tests, opt-in on their
#                                own)
#   oauth2/store/redis           the oauth2 store on Redis
#
# Every variable below must name a disposable server: the tests create a
# namespace of their own (schema, database or key prefix) and drop it
# afterwards. The run fails when a variable is missing, when a test fails,
# when a suite runs no test, and when any test is skipped: a real-backend
# test skips while its variable is unset, so a skip means a server this
# run does not provide. A new real-backend test follows that rule, and its
# variable is added here and to the job.
#
# Locally (Docker), the sqlstores compose file and the Redis of the
# oidcstack one provide every server:
#
#   export SQLSTORES_DB_PASSWORD="$(openssl rand -hex 16)"
#   export OIDCCLIENT_DB_PASSWORD="$(openssl rand -hex 16)"
#   docker compose -f internal/interop/sqlstores/compose.yaml up -d --wait
#   docker compose -f internal/interop/oidcstack/compose.yaml up -d --wait redis
#   pg="postgres://sqlstores:$SQLSTORES_DB_PASSWORD@127.0.0.1:35432/sqlstores?sslmode=disable"
#   my="root:$SQLSTORES_DB_PASSWORD@tcp(127.0.0.1"
#   export SQLSTORES_POSTGRES_DSN="$pg" OIDCCLIENT_POSTGRES_DSN="$pg" SAMLSP_POSTGRES_DSN="$pg"
#   export SQLSTORES_MYSQL80_DSN="$my:33306)/" OIDCCLIENT_MYSQL_DSN="$my:33306)/" SAMLSP_MYSQL_DSN="$my:33306)/"
#   export SQLSTORES_MYSQL84_DSN="$my:33307)/" SQLSTORES_MARIADB_DSN="$my:33308)/"
#   export OIDCCLIENT_REDIS_ADDR=127.0.0.1:26379 SAMLSP_REDIS_ADDR=127.0.0.1:26379 OAUTH2_TEST_REDIS_ADDR=127.0.0.1:26379
#   make test-backends
#
# then stop them: docker compose -f <each file> down.
set -eu

cd "$(dirname "$0")/.."

command -v jq >/dev/null 2>&1 || {
	echo "test-backends: jq is required" >&2
	exit 1
}

missing=
for var in SQLSTORES_POSTGRES_DSN SQLSTORES_MYSQL80_DSN SQLSTORES_MYSQL84_DSN SQLSTORES_MARIADB_DSN \
	OIDCCLIENT_POSTGRES_DSN OIDCCLIENT_MYSQL_DSN OIDCCLIENT_REDIS_ADDR \
	SAMLSP_POSTGRES_DSN SAMLSP_MYSQL_DSN SAMLSP_REDIS_ADDR \
	OAUTH2_TEST_REDIS_ADDR; do
	eval "value=\${$var:-}"
	[ -n "$value" ] || missing="$missing $var"
done
if [ -n "$missing" ]; then
	echo "test-backends: set$missing (see scripts/test-backends.sh)" >&2
	exit 1
fi

mkdir -p build
failed=

# The go test -json events of a file; a line that is not JSON (it should
# not happen) becomes an output event, so that it is printed, not lost.
# shellcheck disable=SC2016 # a jq program: $line is jq's, not the shell's
events='. as $line | try fromjson catch {Action: "output", Output: ($line + "\n")}'

# suite MODULE PACKAGES [SKIP]: runs the tests of PACKAGES in MODULE but
# those SKIP matches, prints their log, and records MODULE as failed when
# a test fails, a test is skipped or no test runs.
suite() {
	out="$PWD/build/backends-$(printf '%s' "$1" | tr / -).json"
	echo "==> $1"
	status=0
	if [ -n "${3:-}" ]; then
		(cd "$1" && go test -race -count=1 -timeout 300s -json -skip "$3" "$2" >"$out") || status=$?
	else
		(cd "$1" && go test -race -count=1 -timeout 300s -json "$2" >"$out") || status=$?
	fi
	jq -Rj "$events"' | select(.Action == "output" or .Action == "build-output") | .Output' "$out"
	skipped=$(jq -Rr "$events"' | select(.Action == "skip" and .Test != null) | .Test' "$out")
	passed=$(jq -Rn "[inputs | $events"' | select(.Action == "pass" and .Test != null)] | length' "$out")
	if [ "$status" -ne 0 ]; then
		failed="$failed $1"
		echo "test-backends: $1: FAILED (go test exited with $status)" >&2
	elif [ -n "$skipped" ]; then
		failed="$failed $1"
		printf '%s\n' "$skipped" >&2
		echo "test-backends: $1: FAILED: the tests above were skipped, a server this run does not provide" >&2
	elif [ "$passed" -eq 0 ]; then
		failed="$failed $1"
		echo "test-backends: $1: FAILED: no test ran" >&2
	else
		echo "test-backends: $1: $passed tests passed, none skipped"
	fi
}

suite internal/interop/sqlstores ./...
suite internal/interop/oidcstack .
suite internal/interop/saml . '^(TestKeycloakLive|TestCaptureKeycloakFixture|TestE2EHelperProcess)$'
suite oauth2/store/redis ./...

if [ -n "$failed" ]; then
	echo "test-backends: failed:$failed" >&2
	exit 1
fi

echo "test-backends: ok"
