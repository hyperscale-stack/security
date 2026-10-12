#!/bin/sh
# Copyright 2026 Hyperscale. All rights reserved.
# Use of this source code is governed by a MIT
# license that can be found in the LICENSE file.
#
# Checks that every module stands on its own, as consumers and Dependabot
# see it (`make check-modules`, run by CI on every change and before every
# release):
#
#   1. go.work and every go.mod (the tool modules included) carry the same
#      go line, and none has a toolchain line;
#   2. go.work lists every module but the tool modules (tools/*), so that
#      Dependabot's go.work mode covers them all;
#   3. `go work sync` changes nothing: each module declares the versions the
#      workspace builds and tests with;
#   4. without the generated mocks (what `go mod tidy` and Dependabot see),
#      every module and tool module is tidy outside the workspace;
#   5. with them (what the tests compile), every module builds, vets and is
#      still tidy outside the workspace (GOWORK=off).
#
# When step 3 fails, the files `go work sync` rewrote stay on disk: review
# them and commit them, or run `make tidy`.
set -eu

cd "$(dirname "$0")/.."

fail() {
	echo "check-modules: $*" >&2
	exit 1
}

all=$(find . -name go.mod -not -path '*/vendor/*' -not -path '*/node_modules/*' -not -path './build/*' |
	sort | sed 's|/go\.mod$||')
workspace=$(printf '%s\n' "$all" | grep -v '^\./tools/')
tools=$(printf '%s\n' "$all" | grep '^\./tools/' || true)

echo "==> one go line, no toolchain line"
want=$(sed -n 's/^go[[:space:]]\{1,\}\([0-9][0-9.]*\)$/\1/p' go.work)
[ -n "$want" ] || fail "go.work declares no go line"
for mod in $all; do
	got=$(sed -n 's/^go[[:space:]]\{1,\}\([0-9][0-9.]*\)$/\1/p' "$mod/go.mod")
	[ "$got" = "$want" ] ||
		fail "$mod/go.mod declares go $got, go.work go $want: bump every go line together"
	! grep -q '^toolchain' "$mod/go.mod" ||
		fail "$mod/go.mod has a toolchain line: the go line is the toolchain floor"
done
! grep -q '^toolchain' go.work || fail "go.work has a toolchain line"

echo "==> go.work lists every module"
listed=$(awk '
	/^use[[:space:]]*\(/ { block = 1; next }
	block && /^\)/ { block = 0; next }
	block { print $1; next }
	/^use[[:space:]]/ { print $2 }
' go.work)
for mod in $workspace; do
	printf '%s\n' "$listed" | grep -qx "$mod" ||
		fail "$mod is not listed in go.work (go work use $mod): Dependabot would not update it"
done

echo "==> go work sync is a no-op"
manifests() {
	for mod in $workspace; do
		cat "$mod/go.mod"
		[ ! -f "$mod/go.sum" ] || cat "$mod/go.sum"
	done | cksum
}
before=$(manifests)
go work sync
[ "$before" = "$(manifests)" ] ||
	fail "go work sync rewrote go.mod/go.sum files (left on disk): review and commit them, or run make tidy"

echo "==> tidy without the generated mocks"
"${MAKE:-make}" --no-print-directory clean-mocks
for mod in $all; do
	(cd "$mod" && GOWORK=off go mod tidy -diff) ||
		fail "$mod is not tidy without the generated mocks (diff above): run make tidy; if only generated mocks import testify/mock, the module needs a mockery_test.go importing it"
done

echo "==> build, vet and tidy with the generated mocks"
"${MAKE:-make}" --no-print-directory generate
for mod in $workspace; do
	echo "    $mod"
	(cd "$mod" && GOWORK=off go build ./... && GOWORK=off go vet ./... && GOWORK=off go mod tidy -diff) ||
		fail "$mod does not build, vet or stay tidy on its own (GOWORK=off)"
done
for mod in $tools; do
	(cd "$mod" && GOWORK=off go mod tidy -diff) || fail "$mod is not tidy"
done

echo "check-modules: ok"
