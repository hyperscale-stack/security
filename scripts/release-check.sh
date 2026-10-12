#!/bin/sh
# Copyright 2026 Hyperscale. All rights reserved.
# Use of this source code is governed by a MIT
# license that can be found in the LICENSE file.
#
# Checks a release tag before it is pushed (`make release-check TAG=...`)
# and again in the release workflow (docs/releasing.md):
#
#   - TAG is vMAJOR.MINOR.PATCH[-PRERELEASE] for the core module, or
#     <dir>/vMAJOR.MINOR.PATCH[-PRERELEASE] for the module in <dir>, as a
#     canonical semantic version without build metadata (the go command
#     ignores any other tag), and the major version is 1: the module paths
#     carry no /vN suffix, so the go command would ignore a v2+ tag, and a
#     v0.x release is not planned;
#   - <dir> holds a released module (not examples/, internal/ or tools/)
#     whose go.mod declares the matching module path;
#   - that go.mod requires real versions of the in-repo modules, never the
#     v0.0.0-00010101000000-000000000000 placeholder;
#   - the commit (HEAD) is on origin/master;
#   - the module builds and vets as a consumer resolves it: a copy without
#     its in-repo replace directives, outside the workspace, so that the
#     in-repo modules it requires are fetched at their required versions
#     (they must be tagged and pushed first).
#
# In GitHub Actions it also writes the module directory, the previous tag of
# the same module and whether the version is a pre-release to $GITHUB_OUTPUT.
set -eu

ROOT=github.com/hyperscale-stack/security
ROOT_RE='github\.com/hyperscale-stack/security'
PLACEHOLDER=v0.0.0-00010101000000-000000000000

fail() {
	echo "release-check: $*" >&2
	exit 1
}

tag=${1:-}
[ -n "$tag" ] || fail "usage: release-check.sh TAG (v1.2.3 for the core module, <dir>/v1.2.3 otherwise)"

cd "$(dirname "$0")/.."

case $tag in
*/*)
	dir=${tag%/*}
	version=${tag##*/}
	;;
*)
	dir=.
	version=$tag
	;;
esac

num='(0|[1-9][0-9]*)'
ident='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
printf '%s\n' "$version" | grep -Eq "^v$num\\.$num\\.$num(-$ident(\\.$ident)*)?\$" ||
	fail "$tag: the version must be a canonical vMAJOR.MINOR.PATCH[-PRERELEASE] (no leading zeros, no build metadata)"
printf '%s\n' "$version" | grep -q '^v1\.' ||
	fail "$tag: only v1 releases are made (the module paths have no /vN suffix; v0.x needs an explicit decision)"

case $dir in
examples | examples/* | internal | internal/* | tools | tools/*)
	fail "$tag: $dir is never released"
	;;
esac
printf '%s\n' "$dir" | grep -Eq '^(\.|[a-z0-9]+(/[a-z0-9]+)*)$' || fail "$tag: malformed module directory $dir"
[ -f "$dir/go.mod" ] || fail "$tag: no module in $dir"

expected=$ROOT
[ "$dir" = . ] || expected=$ROOT/$dir
path=$(sed -n 's/^module[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' "$dir/go.mod")
[ "$path" = "$expected" ] || fail "$tag: $dir/go.mod declares module $path, want $expected"

if grep -n -- "$PLACEHOLDER" "$dir/go.mod" >&2; then
	fail "$tag: $dir/go.mod requires in-repo modules at the placeholder version above; set each to its release tag first (docs/releasing.md)"
fi

git rev-parse -q --verify refs/remotes/origin/master >/dev/null || fail "origin/master is unknown: git fetch origin"
git merge-base --is-ancestor HEAD origin/master || fail "HEAD is not on origin/master: release from master"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
	prefix=
	[ "$dir" = . ] || prefix=$dir/
	previous=$(git tag --list "${prefix}v[0-9]*" --sort=v:refname |
		awk -v cur="$tag" '$0 == cur { print prev; exit } { prev = $0 }')
	prerelease=false
	case $version in
	*-*) prerelease=true ;;
	esac
	{
		echo "dir=$dir"
		echo "previous=$previous"
		echo "prerelease=$prerelease"
	} >>"$GITHUB_OUTPUT"
fi

echo "==> $tag: build and vet $expected as a consumer resolves it"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -R "$dir"/. "$tmp"/
cd "$tmp"
! grep -q '^replace[[:space:]]*(' go.mod || fail "$tag: replace blocks are not supported, use one replace line per module"
for old in $(sed -n 's/^replace[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' go.mod | grep -E "^$ROOT_RE(/|\$)" || true); do
	go mod edit -dropreplace="$old"
done
GOWORK=off GOFLAGS=-mod=mod go build ./... ||
	fail "$tag: $expected does not build at the versions it requires (are its in-repo requirements tagged and up to date?)"
GOWORK=off GOFLAGS=-mod=mod go vet ./... ||
	fail "$tag: $expected does not vet at the versions it requires"

echo "release-check: $tag ok"
