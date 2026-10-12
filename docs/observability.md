# Observability

Every module instruments its long-lived operations with OpenTelemetry
spans. Instrumentation lives directly inside the module that owns the
operation — there is no central audit or event-sink package. To collect the
spans, install a `TracerProvider` from the OpenTelemetry SDK in your
application; the library uses the global provider via `otel.Tracer`.

## Instrumentation scopes

Each module reports under a stable instrumentation scope (the tracer name):

| Module          | Instrumentation scope                             |
| --------------- | ------------------------------------------------- |
| core            | `github.com/hyperscale-stack/security`            |
| `httpsec`       | `github.com/hyperscale-stack/security/http`       |
| `grpcsec`       | `github.com/hyperscale-stack/security/grpc`       |
| `connectrpcsec` | `github.com/hyperscale-stack/security/connectrpc` |
| `jwtsec`        | `github.com/hyperscale-stack/security/jwt`        |
| `session`       | `github.com/hyperscale-stack/security/session`    |
| `samlsp`        | `github.com/hyperscale-stack/security/saml/sp`    |

The `basic`, `bearer`, `password`, `oauth2` and `oidc/provider` modules do
not open spans of their own — keeping them free of a direct `go.opentelemetry.io/otel`
dependency. Basic/Bearer authentication is still observable: the core
`security.Manager.Authenticate` span records which authenticator ran via
the `security.authenticator.name` attribute and an `authenticator.try`
event per candidate. OAuth2 HTTP endpoints are observable through the host
server's HTTP instrumentation (e.g. `otelhttp`) and, for their errors,
through the OAuth2 error hook described below.

The OpenID Connect client (`oidc/client`, its stores) and the core's
`outbound` package open no spans either: every failure is returned to the
caller as a sentinel error (`errors.Is`) that carries no secret.
`Config`, `*Client`, `Callback`, `AuthRequest`, `Identity` and `Tokens`
redact their secrets with every `fmt` verb and in `slog` output, and
`Identity` and `UserInfo` log their identifiers only (`LogValue`). Log the error of `Complete` or
`HandleCallback`.

## OAuth2 error hook

An RFC 6749 §5.2 response carries a code, a description and a URI — never
the cause. A `server_error` therefore reaches the client as an opaque 500,
and a revocation that may not have taken effect as a bare
`503 temporarily_unavailable` (RFC 7009 §2.2.1). Both are protocol
requirements, and both leave an operator with nothing to diagnose.

`oauth2.ServerConfig.OnError` closes that gap. It is an `oauth2.ErrorHook`
(`func(ctx context.Context, err error)`) called with the `*oauth2.Error`
envelope — cause intact — at the point the server decides on its answer:

```go
srv, err := oauth2.NewServer(oauth2.ServerConfig{
    // ...
    OnError: func(ctx context.Context, err error) {
        if oauth2.IsCode(err) != oauth2.CodeServerError {
            return // expected 4xx traffic
        }

        slog.ErrorContext(ctx, "oauth2 server error", "err", err)
    },
})
```

The hook fires for:

- every error serialized as an RFC 6749 §5.2 body (`/token`, `/revoke`,
  `/introspect`, metadata) — a failed client authentication as the constant
  `invalid_client` the wire carries, the refusal it replaced ("unknown
  client", "method not allowed for client"…) in its cause — and every error
  redirected back to the client by
  `/authorize`, including the pre-redirect refusals answered with a bare
  400 (unknown client, unregistered `redirect_uri`, a registered
  `redirect_uri` `oauth2.ValidateRedirectURI` refuses — `invalid registered
  redirect_uri`, the `ErrInvalidRedirectURI` refusal as cause — and a
  request too large or malformed);
- every storage failure at `/revoke`: a token lookup that failed for another
  reason than an unknown token (`revoke: token lookup failed`), and a failed
  family or access-token revocation (`revoke refresh family failed`,
  `revoke access token failed`) — one `server_error` per failure, cause
  attached. When the failure leaves the revocation unfinished — a failed
  lookup, a family that could not be revoked, a token outside any family
  that could not be deleted — `/revoke` answers
  `503 temporarily_unavailable` (RFC 7009 §2.2.1: the client must assume the
  token still exists, and may retry); that 503 is not reported again. An
  access token whose family was revoked but whose delete failed answers
  `200 OK`: it is unusable through its family. An unknown token, or another
  client's, answers `200 OK` and is not reported;
- an `IntrospectionPolicy` that failed: `/introspect` withholds the token
  behind a bare `{"active":false}` and reports a `server_error`
  (`introspection policy failed`, the policy's error as cause). A plain
  refusal by the policy is an expected outcome and is not reported;
- at `/authorize`, an unsupported `response_mode` (`invalid_request`, answered
  with a bare 400), a failing `IssuerResolver`, a failing `ConsentFunc`
  (`consent handler failed`, its error as cause), a `Consent.Refusal` (as
  returned), an approval without a valid subject, and every error of an
  `oauth2.Extension` hook — a protocol code as returned, anything else as a
  `server_error` (`authorization extension failed`) carrying it. An error
  whose code the endpoint cannot send reaches the hook as a `server_error`
  whose cause is the original. An error answered with a bare page because
  `AuthorizeConfig.TrustedRedirect` does not trust the client reaches the
  hook exactly as it would have been redirected;
- at `/token`, an `ExtendTokenResponse` failure: its `invalid_grant` as
  returned, anything else as a `server_error` carrying it.

The `oidc/provider` OpenID Provider reports through the same
`ServerConfig.OnError`: its `/authorize` and `/token` refusals travel as the
extension errors above — a contract violation by the application's
`Interaction`, a key source or claims source failure, an invalid issuer, all
as a `server_error` carrying the cause — and its own handlers report theirs
directly: every UserInfo refusal as an `*oauth2.Error` with its RFC 6750 code
(`invalid_request`, `invalid_token`, `insufficient_scope`) and cause, and a
discovery, JWK Set or UserInfo failure as a `server_error`. A UserInfo request
without a token is not reported. Causes never carry a token, an
`id_token_hint`, a `nonce`, a `login_hint` or a claim value.

`grant.Config.OnError` is the same hook for the errors a grant swallows
before returning — today, a family revocation that failed after a
refresh-token reuse (RFC 9700 §4.14.2), whether the grant found the
presented token consumed or the store reported the reuse while rotating,
or after an authorization-code replay (RFC 6749 §4.1.2). These revocations
run on a context detached from the request, and the `refresh_token` grant
retries one the store could not record. The hook gets one `server_error`
per revocation that still failed — `revoke refresh family failed after
reuse detection`, or `revoke token family failed after authorization code
replay` — whose cause matches `oauth2.ErrTokenFamilyRevocationFailed` and
names the family with a conforming store. It does not match
`oauth2.ErrRefreshTokenReused` or `oauth2.ErrCodeAlreadyUsed`: the reuse or
replay itself is the `invalid_grant` the server reports as usual. Errors a
grant *returns* travel to the server and reach `ServerConfig.OnError`, so
wire both fields to the same sink.

The hook is purely observational: it MUST NOT influence the response, and it
runs synchronously on the request goroutine, so keep it fast. It receives no
secret — the envelope carries the code, the description and the wrapped Go
error, never a token or a client secret — but the cause comes from your own
storage layer, so apply the same redaction rules you apply to your logs.

## Span catalog

### Core — `github.com/hyperscale-stack/security`

| Span                                   | When                                   | Attributes                                                                       | Error status                                              |
| --------------------------------------- | --------------------------------------- | --------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `security.Engine.Process`               | `Engine.Process` — extract + authenticate | `security.extractors.count` (int), `security.authenticated` (bool); `error.type` (string, on failure) | `ErrNoExtractor`, extractor error, or manager error        |
| `security.Manager.Authenticate`         | `Manager.Authenticate` — chain authenticators | `security.authenticators.count` (int), `security.authenticated` (bool, on success), `security.authenticator.name` (string, on success); event `authenticator.try` per candidate; `error.type` (string, on failure) | `ErrUnsupportedCredential`, `ErrAuthenticatorRefused`      |
| `security.AccessDecisionManager.Decide` | `AccessDecisionManager.Decide`          | `security.strategy` (string), `security.attributes` (string, joined), `security.decision` (string); `security.attributes.unsupported` (int, when an attribute is supported by no voter); `error.type` (string, on denial) | `ErrAccessDenied` when the final decision is not Grant     |

A failing core span records **the class of its error, never the error
text**: the status description and the OpenTelemetry `error.type` attribute
are `security.ErrorClass(err)` — `invalid_credentials`, `token_expired`,
`unavailable`, `access_denied`, … or `_OTHER` for an error that wraps no
security sentinel — and no `exception` event is added. The error text can
hold user input (a username, a password typed in the username field) and
the wrapped errors of your stores; it reaches only the caller, which may log
it server-side. `error.type` is not set on success.

`security.principal.subject` is a **reserved** attribute key. It is not
emitted by default — subject identifiers are PII and high-cardinality. Wire
it yourself only behind a deliberate, low-cardinality (hashed) opt-in.

### HTTP — `github.com/hyperscale-stack/security/http`

| Span                | When                          | Attributes                                                          | Error status            |
| ------------------- | ----------------------------- | -------------------------------------------------------------------- | ----------------------- |
| `httpsec.Middleware` | Per request through `Middleware` | `http.request.method` (string), `http.route` (string, when known), `security.handled` (bool) | inherited from the core |

`httpsec.Middleware` is the parent span of the core `security.Engine.*`
spans for that request. `httpsec.Authorize` does **not** open its own span —
it delegates to `security.AccessDecisionManager.Decide`.

Both HTTP attributes follow the OpenTelemetry semantic conventions and carry
no client-chosen value: `http.request.method` is one of the RFC 9110 / RFC
5789 methods, matched exactly, or `_OTHER` (the original method is left to
the server span of `otelhttp`); `http.route` is the path template of the
`ServeMux` pattern that routed the request (`/items/{id}`) — set only when
the middleware runs inside a route, never the raw path.

### gRPC — `github.com/hyperscale-stack/security/grpc`

| Span                   | When                                            | Attributes                                                  | Error status            |
| ---------------------- | ----------------------------------------------- | ------------------------------------------------------------ | ----------------------- |
| `grpcsec.Authenticate` | Per RPC, unary and stream interceptors          | `rpc.method` (string), `security.authenticated` (bool)       | inherited from the core |
| `grpcsec.Authorize`    | `UnaryAuthorize` / `StreamAuthorize`            | none directly — delegates to `security.AccessDecisionManager.Decide` | inherited from the core |

`grpcsec` deliberately does **not** open an `rpc` span — that belongs to
`otelgrpc`, which you compose alongside these interceptors. `rpc.method` is
the full method gRPC routed the call to; behind a `grpc.UnknownServiceHandler`
it is the name the client sent.

### ConnectRPC — `github.com/hyperscale-stack/security/connectrpc`

| Span                         | When                                       | Attributes                                                          | Error status            |
| ---------------------------- | ------------------------------------------ | -------------------------------------------------------------------- | ----------------------- |
| `connectrpcsec.Authenticate` | Per RPC, unary and streaming interceptors  | `rpc.method` (string), `security.authenticated` (bool)               | inherited from the core |
| `connectrpcsec.Authorize`    | The authorization interceptor              | none directly — delegates to `security.AccessDecisionManager.Decide` | inherited from the core |

`connectrpcsec` deliberately does **not** open an `rpc` span — that belongs
to `otelconnect`, which you compose alongside these interceptors.

### JWT — `github.com/hyperscale-stack/security/jwt`

| Span                  | When               | Attributes                                              | Error status                                                        |
| --------------------- | ------------------ | -------------------------------------------------------- | --------------------------------------------------------------------- |
| `jwtsec.Signer.Sign`  | `Signer.Sign`      | `jwt.alg` (string), `jwt.kid` (string)                  | —                                                                     |
| `jwtsec.Verifier.Verify` | `Verifier.Verify` | `jwt.alg` (string), `jwt.kid` (string, clipped), `jwt.iss` (string, clipped) | `parse` (size bound, encoding, header, disallowed alg), `typ`, `kid` (no single key, key set unavailable, key bound to another algorithm or invalid), `signature`, `unmarshal` (claims), `claims` |
| `jwtsec.VerifySignature` | `VerifySignature` | `jwt.alg` (string), `jwt.kid` (string, clipped)         | `parse` (disallowed alg included), `kid` (no single key, key bound to another alg or invalid), `signature` |
| `jwtsec.RemoteJWKS.Fetch` | a fetch of the remote JWK Set — a new root span (the fetch outlives the request that started it) linked to the caller's span | `jwt.jwks.url` (string, without userinfo, query or fragment), `jwt.jwks.keys` (int, kept), `jwt.jwks.ignored` (int, unusable keys skipped) | `fetch` |

Values taken from a token (`jwt.kid`, `jwt.alg` of a refused token,
`jwt.iss`) and the third-party messages that recorded errors quote — a
parser's, or a transport's quoting what the JWK Set host sent — are clipped
to 128 bytes; the errors `KeySet` returns name the remote JWK Set's URL once,
without userinfo or query (the `jwtsec.RemoteJWKS.Fetch` span carries it in
`jwt.jwks.url`).

### Session — `github.com/hyperscale-stack/security/session`

| Span                     | When                | Attributes                                                       | Error status |
| ------------------------ | ------------------- | ----------------------------------------------------------------- | ------------ |
| `session.Manager.Login`  | `Manager.Login`     | `session.id_hash` (string)                                        | —            |
| `session.Manager.Get`    | `Manager.Get`       | `session.id_hash` (string, on success)                            | —            |
| `session.Manager.Touch`  | `Manager.Touch`     | none                                                              | —            |
| `session.Manager.Rotate` | `Manager.Rotate`    | `session.old_id_hash` (string), `session.new_id_hash` (string)    | —            |
| `session.Manager.Logout` | `Manager.Logout`    | none                                                              | —            |

Session IDs are never placed on a span raw — `session.*id_hash` attributes
carry a non-reversible SHA-256 fingerprint for correlation only.

### SAML SP — `github.com/hyperscale-stack/security/saml/sp`

| Span                                    | When                          | Attributes                                                                                                                         | Error status                    |
| --------------------------------------- | ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `samlsp.ServiceProvider.BeginLogin`     | `ServiceProvider.BeginLogin`    | `samlsp.connection_id` (string), `samlsp.idp_entity_id` (string), `samlsp.insecure_sha1` (bool, when set), `samlsp.outcome` (string), `samlsp.reason` (string, on failure) | any error                       |
| `samlsp.ServiceProvider.CompleteLogin`  | `ServiceProvider.CompleteLogin` | same as `BeginLogin`, plus `samlsp.transaction_consumed` (bool, when the call consumed the login transaction)                     | any error                       |
| `samlsp.FetchMetadata`                  | every metadata download (`FetchIdentityProviderMetadata`, `MetadataSource`) | `samlsp.outcome` (string), `samlsp.reason` (string, on failure: `metadata_unavailable`, `invalid_metadata`, `metadata_expired`) | any error |

`samlsp.outcome` is `success`, `rejected` (the error matches
`samlsp.ErrRejected`: the login was refused) or `error` (an
infrastructure or configuration failure). `samlsp.reason` names the
sentinel in snake case — `audience_mismatch`, `assertion_replayed`,
`missing_browser_binding`… — so refusals can be counted per cause:
`transaction_integrity` reports a transaction altered in the store (or
instances that do not share the transaction keys), `origin_mismatch` an ACS
POST from another origin than the connection's `ResponseOrigins`. A
rejected `CompleteLogin` carrying `samlsp.transaction_consumed` ended the
login (one verification per login: the user must start over); one without
it left the transaction to its browser. The connection attributes are set
once the connection is resolved. No span
carries a NameID, an attribute value, a RelayState handle, the binding
cookie, a request or assertion ID, a metadata URL or address, or any
message content, and error messages are not recorded. A `MetadataSource`
serving cached metadata opens no span: only downloads do.

## Secrets policy

No span attribute ever carries a secret: cleartext passwords, access or
refresh tokens, authorization codes, client secrets, raw session IDs, or
SAML assertions, NameIDs, RelayState handles and binding cookies. The core,
`session` and `samlsp` spans never record an error message either: only its
class.
Where correlation is genuinely needed, the value is hashed first
(`session.id_hash`). When you add your own instrumentation around this
library, keep the same rule.

## Verifying spans in tests

The test suites use the OpenTelemetry SDK's in-memory exporter
(`tracetest.NewSpanRecorder`) to assert span names, attributes, and status.
Apply the same pattern in your own integration tests, or run any example
with `OTEL_TRACES_EXPORTER=console` to see the spans on stdout.
