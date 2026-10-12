# Releasing

The repository is a Go workspace of independently released modules. This
checklist cuts releases that consumers can resolve. Outside this repository
the go command ignores the `replace` directives of a dependency, so a tagged
`go.mod` must require real, published versions of the in-repo modules it
uses.

## Versions and tags

- The first release of every module is **`v1.0.0`**. The module paths carry
  no `/vN` suffix, so the go command would ignore a `v2.x.y` tag (semantic
  import versioning). `scripts/release-check.sh` only accepts
  `v1.MINOR.PATCH[-PRERELEASE]`; a `v0.x` release would need an explicit
  decision.
- The core module is tagged `vX.Y.Z`. The module in `<dir>` is tagged
  `<dir>/vX.Y.Z`: `http/v1.0.0`, `oidc/client/v1.0.0`,
  `oauth2/store/sql/v1.0.0`…
- A version is a canonical semantic version: no leading zeros, no build
  metadata (`+…`). The go command ignores any other tag.
- `examples`, `internal/*` (test-only modules) and `tools/*` (development
  tools) are never released.

## Release order

A module can only be released once the in-repo modules it requires are
tagged and published. Tag in dependency order (a module's in-repo
requirements are the `github.com/hyperscale-stack/security…` lines of its
`go.mod`):

1. `v1.0.0` (core), `password/v1.0.0`.
2. `basic` (core, password); `bearer`, `connectrpc`, `grpc`, `http`,
   `oauth2`, `oidc/client`, `saml/sp`, `session` (core).
3. `jwt` (core, bearer, oauth2); `oauth2/store/redis`, `oauth2/store/sql`
   (oauth2); `oidc/client/store/redis`, `oidc/client/store/sql`
   (oidc/client); `saml/sp/store/redis`, `saml/sp/store/sql` (saml/sp).
4. `oidc/provider` (core, bearer, jwt, oauth2).

## Checklist

1. **master is green.** The `Go` and `govulncheck` workflows passed on the
   commit to release, and no reachable advisory is open (see below).
2. **Release commit** (a pull request to master):
   - `CHANGELOG.md`: turn `[Unreleased]` into `[1.0.0] - YYYY-MM-DD`.
   - Set every in-repo requirement of every module of this release to its new
     version. For example, in `oauth2/store/sql`:

     ```sh
     cd oauth2/store/sql
     go mod edit -require=github.com/hyperscale-stack/security@v1.0.0 \
                 -require=github.com/hyperscale-stack/security/oauth2@v1.0.0
     ```

     Keep the `replace` lines. They only apply inside this repository, so
     local development and CI keep building the code on disk, while
     consumers resolve the versions above.
   - `make tidy && make check-modules`, then merge.
3. **Tag, check and push one module at a time**, in the order above, on the
   release commit:

   ```sh
   git fetch origin && git checkout <release commit>
   make release-check TAG=oauth2/store/sql/v1.0.0
   git tag -a oauth2/store/sql/v1.0.0 -m "oauth2/store/sql v1.0.0"
   git push origin oauth2/store/sql/v1.0.0
   ```

   `make release-check` refuses:
   - a malformed or non-v1 tag;
   - a module that is never released;
   - a placeholder requirement (`v0.0.0-00010101000000-000000000000`);
   - a commit that is not on `origin/master`.

   It then builds and vets a copy of the module **without its in-repo
   `replace` directives**, outside the workspace. That is exactly what a
   consumer resolves: the in-repo requirements are fetched from the module
   proxy at their required versions. So it fails until those requirements
   are tagged and pushed (keep the order), and whenever the module uses code
   that its required versions lack.
4. **The Release workflow** (`.github/workflows/release.yml`) runs on every
   `v*` and `**/v*` tag, with a read-only token:
   - the same check, then `make check-modules build test lint vuln`;
   - only then a separate job creates the GitHub release, with
     `contents: write`, no checkout and no third-party action;
   - `-rc` versions are published as pre-releases, and a sub-module release
     is never marked "latest" (the README badge shows the core's).

   Wait for it before pushing a tag that depends on this one.
5. **Consumer check**, once every tag is published:

   ```sh
   cd "$(mktemp -d)" && go mod init example.com/check
   go get github.com/hyperscale-stack/security/oidc/provider@v1.0.0
   go build github.com/hyperscale-stack/security/oidc/provider/...
   ```

## Toolchain and vulnerabilities

- `go.work` and every `go.mod` carry the same `go` line, which consumers
  inherit as their minimum (`make check-modules` enforces it). When a Go
  release fixes a standard-library advisory that the `govulncheck` workflow
  reports:
  1. bump `go.work` and every `go` line together (`go work edit -go=…`,
     `go mod edit -go=…` in each module and tool module);
  2. release patch versions of the affected modules.
- The `govulncheck` workflow runs on every change, weekly, and inside the
  release workflow. An advisory with no fixed version keeps it red. Triage
  it:
  - remove the call path if you can;
  - otherwise record the decision in `docs/security-considerations.md`:
    advisory ID, why it is not exploitable or is accepted, owner, review
    date.

  The release workflow never publishes over a reachable advisory. A release
  with a documented, accepted advisory is published by hand
  (`gh release create <tag> --verify-tag`).

## Repository settings (maintainer)

These are not versioned in the repository; set them once:

- Actions → General:
  - default workflow permissions **read**;
  - untick "Allow GitHub Actions to create and approve pull requests";
  - require actions to be pinned to a full-length commit SHA.
- Rulesets:
  - `master`: pull request plus the required status check
    `Build & test (workspace)`;
  - tags `v*` and `**/v*`: creation, update and deletion restricted to
    maintainers.
- Releases: enable release immutability, so the tag of a published release
  can no longer be moved or deleted.
- Environments: give `release` (used by the publish job) required reviewers.
- Code security: Dependabot alerts and security updates, secret scanning and
  push protection.
