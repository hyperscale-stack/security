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

1. **master is green.** The `Go` workflow (both jobs: the build and test
   of the workspace, and the store suites on real servers) and the
   `govulncheck` workflow (both jobs: govulncheck and OSV-Scanner) passed on
   the commit to release, no reachable advisory is open, and the advisories
   that no scanner sees were checked by hand (see below).
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

   `make release-check` runs `scripts/release-check.sh`, which needs `git`,
   `go` and `jq` on the `PATH` (GitHub runners have them; without `jq` the
   script stops with "jq is required"). It refuses:
   - a malformed or non-v1 tag;
   - a module that is never released;
   - a placeholder requirement (`v0.0.0-00010101000000-000000000000`);
   - a commit that is not on `origin/master`;
   - any `replace` directive other than the in-repo ones, and any `exclude`
     directive: consumers ignore both, so a release must not need them.

   It then builds and vets a copy of the module **without its in-repo
   `replace` directives**, outside the workspace. That is exactly what a
   consumer resolves: the in-repo requirements are fetched from the module
   proxy at their required versions. So it fails until those requirements
   are tagged and pushed (keep the order), and whenever the module uses code
   that its required versions lack.
4. **The Release workflow** (`.github/workflows/release.yml`) runs on every
   `v*` and `**/v*` tag, with a read-only token:
   - the same check, then `make check-modules build test lint`,
     govulncheck on the released module's own code (outside the workspace,
     tests excluded), and OSV-Scanner on the released module's `go.mod`
     (`make osv OSV_MODULES=<dir>`; every requirement, tests included). The
     full scan of every module is step 1's `govulncheck` workflow;
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
- The `govulncheck` workflow has two jobs. Both scan every module on every
  change and weekly, and both must be green on the commit of a release
  (checklist step 1). Neither is a required check (see the rulesets below).
  - **govulncheck** (`make vuln`): the Go vulnerability database, at symbol
    level, each module outside the workspace, tests included. The standard
    library is scanned at the toolchain CI runs (`go.work`).
  - **OSV-Scanner** (`make osv`, pinned in `tools/osv-scanner`): every
    module's `go.mod` against the OSV database. It adds what the Go
    database lacks: the GitHub-reviewed advisories (GHSA), which usually
    reach the Go database 1 to 7 weeks after GitHub's review, and the
    records the Go team withdrew. Advisories that carry symbol data go
    through Go call analysis, as with govulncheck, so an uncalled one does
    not fail the job. GO-2026-5932, reported for `golang.org/x/crypto`, is
    listed as uncalled: if call analysis ever breaks, it turns the job red.
    An advisory without symbol data, which is what a GHSA-only record is,
    fails whenever a required version is affected, test-only requirements
    included. An error reaching the database fails the job too. The
    standard library is left to govulncheck.
- An advisory with no fixed version keeps a job red. Triage it:
  - remove the call path, or the requirement, if you can;
  - otherwise record the decision in `docs/security-considerations.md`:
    advisory ID, why it is not exploitable or is accepted, owner, review
    date. For OSV-Scanner, also add an `[[IgnoredVulns]]` entry to the root
    `osv-scanner.toml`, with an `ignoreUntil` date at most 90 days ahead
    and the `reason` (the file's header lists the rules). It is the only
    configuration `make osv` reads: an `osv-scanner.toml` next to a
    `go.mod` is ignored.
- The release workflow scans the released module itself with both tools,
  and never publishes over a failing scan:
  - govulncheck on the module's own code, tests excluded. A release with a
    documented, accepted govulncheck advisory is published by hand
    (`gh release create <tag> --verify-tag`);
  - OSV-Scanner on the module's `go.mod`, which is broader: every
    requirement, test-only ones included. An OSV exception goes into
    `osv-scanner.toml` on master, since the release commit must be on
    master; there is no manual bypass.
- **Blind spot: repository advisories that GitHub never reviews.** The
  maintainers of a dependency can publish a security advisory in their own
  repository. It reaches the GitHub Advisory Database, and from there OSV,
  Dependabot alerts and later the Go vulnerability database, only once
  GitHub reviews it, and in practice the advisories without a CVE are not
  reviewed. No scanner above sees them. On 2026-10-21, 15 such advisories
  had been published since July 2026 against 6 dependencies of the
  workspace: `go-jose/go-jose` (4, among them GHSA-mgcc-cww5-fp2q, a High
  denial of service of go-jose v4.1.5), `beevik/etree` (4),
  `russellhaering/gosaml2` (3), `go-chi/chi` (2),
  `russellhaering/goxmldsig` and `zitadel/oidc` (1 each). Before a release,
  read the published advisories of the security-critical dependencies (the
  Security tab of each repository, or
  `gh api repos/<owner>/<repo>/security-advisories`) and compare them with
  the required versions: `go-jose/go-jose`, `russellhaering/goxmldsig`,
  `russellhaering/gosaml2`, `beevik/etree`,
  `mattermost/xml-roundtrip-validator`, `redis/go-redis`,
  `connectrpc/connect-go`, `grpc/grpc-go`, `open-telemetry/opentelemetry-go`.

## Dependabot

- Version updates: the root `gomod` entry runs in go.work mode and updates
  every workspace module in one PR. The `/tools/*` entry updates the tool
  modules, and the `github-actions` entry updates the SHA pins. A version is
  proposed after a 7-day cooldown.
- Security updates (enabled, see the repository settings) run in the
  directory of the vulnerable module and do not see `go.work`. A PR that
  bumps a dependency in one sub-module leaves the other modules that require
  it out of sync, and `make check-modules` fails ("go work sync rewrote …").
  Check out the PR branch, run `make tidy`, and push the result onto it
  before merging.
- An alert or a security update on a tool module (`tools/<name>`): no
  scanner covers the tool modules (they hold no package to analyse), so
  Dependabot is the only signal. The tools run in CI only, with a read-only
  token and no secret. Prefer a release of the tool that fixes it
  (`cd tools/<name> && GOWORK=off go get -tool <package>@<version>`); when
  there is none, bump the vulnerable module in that tool module alone
  (`GOWORK=off go get <module>@<fixed version>`), then
  `make tools check-modules` and a pull request.
- After a change to `.github/dependabot.yml`, or when the update PRs stop
  coming, run "Check for updates" on each entry (Insights → Dependency graph
  → Dependabot) and read the log.
  - Dependabot's image ships an older Go than the `go` line, so every
    `gomod` job downloads the toolchain (`GOTOOLCHAIN=auto`): look for a
    toolchain download error.
  - For `/tools/*`, check that the five tools are seen: they are
    `// indirect` requirements, allowed by name.
  - Fallback while an entry fails: bump by hand. For a workspace dependency:
    `cd <module> && go get <module path>@<version>`, then `make tidy`. For a
    tool: `cd tools/<name> && GOWORK=off go get -tool <package>@<version>`.
    Then `make check-modules` and a pull request.
- Container images: Dependabot updates neither the service images of the
  `Store suites (real backends)` job (`.github/workflows/go.yml`) nor the
  `compose.yaml` files under `internal/interop/`. They pin the same images
  by digest: bump them together, by hand. `docker buildx imagetools inspect
  <image>:<tag>` prints a tag's current digest, the image index that covers
  every platform.

## Tests of published modules

The tests use mockery mocks that `make generate` writes as in-package
`mock_*_test.go` files, never committed. A module downloaded from the module
proxy has neither those files nor `.mockery.yaml`, so its tests (`go test` or
`go vet` from the module cache, a consumer's `go test all`, a distribution
build) only compile from a repository checkout after `make generate`. The
library code itself builds without them.

## Repository settings (maintainer)

These are not versioned in the repository; set them once:

- Actions → General:
  - default workflow permissions **read**;
  - untick "Allow GitHub Actions to create and approve pull requests";
  - require actions to be pinned to a full-length commit SHA.
- Rulesets:
  - `master`: pull request plus the required status checks
    `Build & test (workspace)` and `Store suites (real backends)`, the
    latter once it has proven stable (its first pull request run, three
    re-runs and the first push to master, all green). A required check is
    matched by its job name: renaming a job of `go.yml` needs the same
    change here, or every pull request waits for a check that never comes;
  - tags `v*` and `**/v*`: creation, update and deletion restricted to
    maintainers.
- Releases: enable release immutability, so the tag of a published release
  can no longer be moved or deleted.
- Environments: give `release` (used by the publish job) required reviewers.
- Code security: Dependabot alerts and security updates, secret scanning and
  push protection.
