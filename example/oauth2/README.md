# Example — OAuth2 client_credentials over HTTP

Minimal end-to-end wiring of the security library: HTTP Basic carrying the
OAuth2 client_id / client_secret pair, the `OAuth2AuthenticationProvider`
verifying it against an in-memory client store, and an `AuthorizeHandler`
gating a private route.

## Run

```sh
go run .
```

The server listens on `:1337`.

## Probe

Public route:

```sh
curl -i http://localhost:1337/
```

Private route, no credentials → `401 Unauthorized`:

```sh
curl -i http://localhost:1337/protected
```

Private route, wrong secret → `401 Unauthorized` (now mapped from
`security.ErrClientSecretMismatch`, previously a silent
`AuthorizeHandler` rejection):

```sh
curl -i -u 5cc06c3b-5755-4229-958c-a515a245aaeb:wrong http://localhost:1337/protected
```

Private route, valid credentials → `200 OK` with `hello <client_id>`:

```sh
curl -i -u 5cc06c3b-5755-4229-958c-a515a245aaeb:WTvuAztPD2XBauomleRzGFYuZawS07Ym \
    http://localhost:1337/protected
```

## What this example does NOT cover

- access-token issuance (`/oauth2/token` endpoint),
- authorization code grant, PKCE,
- refresh token rotation,
- persistent storage,
- JWT-formatted access tokens.

These are slated for Phase 7 of the security library refactor (see
[`../../docs/`](../../docs/) once written, or the architecture report at
[`../../ARCHITECTURE_REPORT.md`](../../ARCHITECTURE_REPORT.md)).
