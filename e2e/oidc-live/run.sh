#!/bin/sh
# Copyright 2026 Hyperscale. All rights reserved.
# Use of this source code is governed by a MIT
# license that can be found in the LICENSE file.
#
# Signs in with a real OpenID Provider account through examples/oidc-client,
# in a visible Chrome window where a person completes the provider's login.
# Opt-in, never in CI, no committed credentials:
#
#   LIVE_OIDC_ISSUER=https://accounts.google.com \
#   LIVE_OIDC_CLIENT_ID=... LIVE_OIDC_CLIENT_SECRET=... \
#   make e2e-oidc-live
#
# Register http://localhost:9000/oidc/live/callback as a redirect URI of the
# client at the provider. An empty LIVE_OIDC_CLIENT_SECRET makes a public
# client. The secret only reaches the relying party's process environment.
# Prerequisites: those of e2e/oidc/run.sh.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
out=$root/build/e2e-oidc-live
rp_port=${OIDC_E2E_RP_PORT:-9000}
rp_url=http://localhost:$rp_port

: "${LIVE_OIDC_ISSUER:?set LIVE_OIDC_ISSUER (see $0)}"
: "${LIVE_OIDC_CLIENT_ID:?set LIVE_OIDC_CLIENT_ID (see $0)}"

for tool in go curl openssl tales; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "e2e-oidc-live: $tool is required" >&2
		exit 1
	}
done

mkdir -p "$out/bin"
(cd "$root/examples" && go build -o "$out/bin/" ./oidc-client)

BASE_URL=$rp_url ADDR=localhost:$rp_port OIDC_CONNECTIONS=live \
	OIDC_LIVE_ISSUER=$LIVE_OIDC_ISSUER OIDC_LIVE_CLIENT_ID=$LIVE_OIDC_CLIENT_ID \
	OIDC_LIVE_CLIENT_SECRET=${LIVE_OIDC_CLIENT_SECRET:-} \
	OIDC_TRANSACTION_KEYS=$(openssl rand -hex 32) \
	"$out/bin/oidc-client" >>"$out/oidc-client.log" 2>&1 &
rp_pid=$!
trap 'kill "$rp_pid" 2>/dev/null || true' EXIT INT TERM

i=0
until curl -fsS -o /dev/null "$rp_url/" 2>/dev/null; do
	i=$((i + 1))
	if [ "$i" -gt 150 ]; then
		echo "e2e-oidc-live: the relying party did not come up (log: $out/oidc-client.log)" >&2
		exit 1
	fi
	sleep 0.2
done

cd "$out"
OIDC_E2E_RP_URL=$rp_url tales test "$root/e2e/oidc-live" --parallel 1 --timeout 10m \
	--report-junit "$out/live.xml"
