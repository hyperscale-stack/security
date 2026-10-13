Hyperscale security [![Last release](https://img.shields.io/github/release/hyperscale-stack/security.svg)](https://github.com/hyperscale-stack/security/releases/latest) [![Documentation](https://godoc.org/github.com/hyperscale-stack/security?status.svg)](https://godoc.org/github.com/hyperscale-stack/security)
====================

[![Go Report Card](https://goreportcard.com/badge/github.com/hyperscale-stack/security)](https://goreportcard.com/report/github.com/hyperscale-stack/security)

| Branch  | Status | Coverage |
|---------|--------|----------|
| master  | [![Build Status](https://github.com/hyperscale-stack/security/workflows/Go/badge.svg?branch=master)](https://github.com/hyperscale-stack/security/actions?query=workflow%3AGo) | [![Coveralls](https://img.shields.io/coveralls/hyperscale-stack/security/master.svg)](https://coveralls.io/github/hyperscale-stack/security?branch=master) |

A transport-agnostic authentication and authorization toolkit for Go —
HTTP, gRPC and ConnectRPC, OAuth2, OpenID Connect login and an OpenID
Provider, SAML 2.0 Service Provider federation, JWT, sessions, and a
composable Voter-based access model. It is shipped as a multi-module
workspace so you import only what you need.

## Modules

| Module                                 | Purpose                                                          |
| -------------------------------------- | ---------------------------------------------------------------- |
| `github.com/hyperscale-stack/security` | Core: `Authentication`, `Engine`, `Manager`, `Voter`, ADM        |
| `…/security/http`                      | `httpsec` — `net/http` middleware + authorization                |
| `…/security/grpc`                      | `grpcsec` — unary/stream interceptors                            |
| `…/security/connectrpc`                | `connectrpcsec` — ConnectRPC auth + authorize interceptors       |
| `…/security/basic`                     | HTTP Basic extractor + authenticator                             |
| `…/security/bearer`                    | Bearer extractor + `TokenVerifier` authenticator                 |
| `…/security/password`                  | BCrypt + Argon2id hashers (`NeedsRehash`)                        |
| `…/security/jwt`                       | `jwtsec` — JWT signer/verifier, JWKS                             |
| `…/security/session`                   | Stateless encrypted cookie sessions + CSRF                       |
| `…/security/oauth2`                    | OAuth2 server: profiles, grants, endpoints, extension points     |
| `…/security/oauth2/store/sql`          | Production OAuth2 storage on `database/sql`                      |
| `…/security/oauth2/store/redis`        | Production OAuth2 storage on Redis                               |
| `…/security/oidc/client`               | `oidcclient` — OpenID Connect Relying Party (code flow + PKCE)   |
| `…/security/oidc/client/store/sql`     | OIDC login-transaction store on `database/sql`                   |
| `…/security/oidc/client/store/redis`   | OIDC login-transaction store on Redis                            |
| `…/security/oidc/provider`             | `oidcprovider` — OpenID Provider: ID Tokens, UserInfo, Discovery |
| `…/security/saml/sp`                   | `samlsp` — SAML 2.0 Service Provider (SP-initiated SSO)          |
| `…/security/saml/sp/store/sql`         | Production SAML SP storage on `database/sql`                     |
| `…/security/saml/sp/store/redis`       | Production SAML SP storage on Redis                              |

The core module also ships `…/security/outbound`, an SSRF-safe
`*http.Client` factory for requests to configuration-supplied URLs.

## Install

Every module requires **Go 1.27.2** or later (`go` line of each `go.mod`);
with the default `GOTOOLCHAIN=auto` an older go command downloads it.

```sh
go get github.com/hyperscale-stack/security
go get github.com/hyperscale-stack/security/http   # and any other module you need
```

## Quick start — HTTP Basic

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/basic"
	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/hyperscale-stack/security/password"
)

func main() {
	// loader is your UserLoader implementation (DB-backed, etc.).
	authenticator := basic.NewAuthenticator(loader, password.NewBCryptHasher(12))

	engine := security.NewEngine(
		security.NewManager(authenticator),
		basic.NewExtractor(),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		auth, _ := security.FromContext(r.Context())
		w.Write([]byte("hello " + auth.Name()))
	})

	srv := &http.Server{
		Addr: ":8080",
		// The challenge advertises the scheme the extractors accept (RFC 7617).
		Handler: httpsec.Middleware(engine, httpsec.WithChallengeScheme("Basic"))(mux),
		// Bound every stage so slow clients cannot hold connections open.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
```

Add authorization with a Voter and an `AccessDecisionManager`:

```go
adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))
mux.Handle("/admin", httpsec.Authorize(adm, security.Role("ADMIN"))(adminHandler))
```

## Documentation

- [docs/architecture.md](docs/architecture.md) — modules, pipelines, design.
- [docs/observability.md](docs/observability.md) — OpenTelemetry span catalog.
- [docs/security-considerations.md](docs/security-considerations.md) — defaults and threat model.
- [docs/oidc-provider.md](docs/oidc-provider.md) — OpenID Provider feature matrix and integration guide.
- [docs/oidc-client.md](docs/oidc-client.md) — OpenID Connect Relying Party feature matrix and integration guide.
- [docs/oidc-conformance.md](docs/oidc-conformance.md) — OpenID Connect coverage, interoperability and conformance-suite runs.
- [docs/saml-sp.md](docs/saml-sp.md) — SAML Service Provider integration guide.
- [docs/migration-from-v0.md](docs/migration-from-v0.md) — upgrading from the v0 stack.
- [docs/releasing.md](docs/releasing.md) — versions, tags and the release checklist.
- [MIGRATION.md](MIGRATION.md) — workspace layout and dependency policy.
- [LIMITATIONS.md](LIMITATIONS.md) — known gaps.
- [examples/](examples) — runnable per-scenario demos.

## Development

```sh
make sync     # go work sync
make build    # build every module
make generate # mockery mocks for the tests (never committed; test/lint/vuln run it first)
make test     # race + coverage
make lint     # golangci-lint with the shared config (pinned in tools/golangci-lint)
make vuln     # govulncheck on every module
make check-modules # every module on its own (GOWORK=off), workspace in sync
make e2e      # opt-in browser suites (Tales and Chrome: docs/saml-sp.md, e2e/oidc/run.sh)
make conformance # opt-in: the OpenID Foundation conformance suite, locally (docs/oidc-conformance.md)
```

## License

Hyperscale security is licensed under [the MIT license](LICENSE.md).
