Hyperscale security [![Last release](https://img.shields.io/github/release/hyperscale-stack/security.svg)](https://github.com/hyperscale-stack/security/releases/latest) [![Documentation](https://godoc.org/github.com/hyperscale-stack/security?status.svg)](https://godoc.org/github.com/hyperscale-stack/security)
====================

[![Go Report Card](https://goreportcard.com/badge/github.com/hyperscale-stack/security)](https://goreportcard.com/report/github.com/hyperscale-stack/security)

| Branch  | Status | Coverage |
|---------|--------|----------|
| master  | [![Build Status](https://github.com/hyperscale-stack/security/workflows/Go/badge.svg?branch=master)](https://github.com/hyperscale-stack/security/actions?query=workflow%3AGo) | [![Coveralls](https://img.shields.io/coveralls/hyperscale-stack/security/master.svg)](https://coveralls.io/github/hyperscale-stack/security?branch=master) |

A transport-agnostic authentication and authorization toolkit for Go —
HTTP, gRPC and ConnectRPC, OAuth2, JWT, sessions, and a composable
Voter-based access model. It is shipped as a multi-module workspace so you
import only what you need.

## Modules

| Module                                              | Purpose                                                         |
| --------------------------------------------------- | --------------------------------------------------------------- |
| `github.com/hyperscale-stack/security`              | Core: `Authentication`, `Engine`, `Manager`, `Voter`, ADM       |
| `…/security/http`                                   | `httpsec` — `net/http` middleware + authorization               |
| `…/security/grpc`                                   | `grpcsec` — unary/stream interceptors                           |
| `…/security/connectrpc`                             | `connectrpcsec` — ConnectRPC auth + authorize interceptors      |
| `…/security/basic`                                  | HTTP Basic extractor + authenticator                            |
| `…/security/bearer`                                 | Bearer extractor + `TokenVerifier` authenticator                |
| `…/security/password`                               | BCrypt + Argon2id hashers (`NeedsRehash`)                       |
| `…/security/jwt`                                    | `jwtsec` — JWT signer/verifier, JWKS                            |
| `…/security/session`                                | Stateless encrypted cookie sessions + CSRF                      |
| `…/security/oauth2`                                 | OAuth2 server: profiles, grants, endpoints                      |
| `…/security/oauth2/store/sql`                       | Production OAuth2 storage on `database/sql`                     |
| `…/security/oauth2/store/redis`                     | Production OAuth2 storage on Redis                              |

## Install

```sh
go get github.com/hyperscale-stack/security
go get github.com/hyperscale-stack/security/http   # and any other module you need
```

## Quick start — HTTP Basic

```go
package main

import (
	"net/http"

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

	http.ListenAndServe(":8080", httpsec.Middleware(engine)(mux))
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
- [docs/migration-from-v0.md](docs/migration-from-v0.md) — upgrading from the v0 stack.
- [MIGRATION.md](MIGRATION.md) — workspace layout and dependency policy.
- [LIMITATIONS.md](LIMITATIONS.md) — known gaps.
- [examples/](examples) — runnable per-scenario demos.

## Development

```sh
make sync     # go work sync
make build    # build every module
make test     # race + coverage
make lint     # golangci-lint with the shared config
```

## License

Hyperscale security is licensed under [the MIT license](LICENSE.md).
