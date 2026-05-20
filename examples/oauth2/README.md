# OAuth2 server + Bearer resource server

End-to-end wiring of the v2 security library running in a single binary:

- an OAuth2 authorization server exposing `/oauth2/token`, `/oauth2/revoke`,
  `/oauth2/introspect`, and `/.well-known/oauth-authorization-server`
  (Profile 2.0 BCP — PKCE / refresh rotation mandatory when relevant);
- a Bearer-protected resource at `GET /protected`, sharing the OAuth2
  storage so it can validate opaque tokens locally (the in-process
  equivalent of RFC 7662 introspection).

## Run

```sh
go run .
```

The server listens on `:1337`.

## Probe — public

```sh
curl -i http://localhost:1337/
```

## Probe — protected without token → `401 Unauthorized`

```sh
curl -i http://localhost:1337/protected
```

## Probe — mint a client_credentials token

```sh
curl -i -u 5cc06c3b-5755-4229-958c-a515a245aaeb:WTvuAztPD2XBauomleRzGFYuZawS07Ym \
    -d 'grant_type=client_credentials&scope=api:read' \
    http://localhost:1337/oauth2/token
```

Response body shape (RFC 6749 §5.1):

```json
{"access_token":"<opaque>","token_type":"Bearer","expires_in":3599,"scope":"api:read"}
```

## Probe — call the protected resource with the issued token

```sh
TOKEN=$(curl -s -u 5cc06c3b-5755-4229-958c-a515a245aaeb:WTvuAztPD2XBauomleRzGFYuZawS07Ym \
    -d 'grant_type=client_credentials&scope=api:read' \
    http://localhost:1337/oauth2/token | jq -r .access_token)
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:1337/protected
```

## Probe — discovery document (RFC 8414)

```sh
curl -s http://localhost:1337/.well-known/oauth-authorization-server | jq
```

## What this example does NOT cover

- `/oauth2/authorize` (consent flow) — deferred to a follow-up slice.
- JWT-formatted access tokens (`jwt.OAuth2AccessTokenSigner` adapter wires
  the JWT module into the token generator; not enabled here).
- Persistent storage (memory store — every restart wipes tokens).
- `private_key_jwt` client authentication.

See [docs/migration-from-v0.md](../../docs/migration-from-v0.md) for the
mapping from the removed v0 stack to this wiring.
