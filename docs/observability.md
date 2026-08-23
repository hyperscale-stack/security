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

The `basic`, `bearer`, `password` and `oauth2` modules do not open spans of
their own — keeping them free of a direct `go.opentelemetry.io/otel`
dependency. Basic/Bearer authentication is still observable: the core
`security.Manager.Authenticate` span records which authenticator ran via
the `security.authenticator.name` attribute and an `authenticator.try`
event per candidate. OAuth2 HTTP endpoints are observable through the host
server's HTTP instrumentation (e.g. `otelhttp`) and, for their errors,
through the OAuth2 error hook described below.

## OAuth2 error hook

An RFC 6749 §5.2 response carries a code, a description and a URI — never
the cause. A `server_error` therefore reaches the client as an opaque 500,
and RFC 7009 §2.2 goes further: a revocation answers `200 OK` even when the
revocation itself failed. Both are protocol requirements, and both leave an
operator with nothing to diagnose.

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
  `/introspect`, metadata) and every error redirected back to the client by
  `/authorize`, including the pre-redirect refusals answered with a bare
  400 (unknown client, unregistered `redirect_uri`);
- the best-effort revocations `/revoke` swallows to honour RFC 7009 §2.2.

`grant.Config.OnError` is the same hook for the errors a grant swallows
before returning — today, a family revocation that failed during BCP §8.10.3
reuse detection. Errors a grant *returns* travel to the server and reach
`ServerConfig.OnError`, so wire both fields to the same sink.

The hook is purely observational: it MUST NOT influence the response, and it
runs synchronously on the request goroutine, so keep it fast. It receives no
secret — the envelope carries the code, the description and the wrapped Go
error, never a token or a client secret — but the cause comes from your own
storage layer, so apply the same redaction rules you apply to your logs.

## Span catalog

### Core — `github.com/hyperscale-stack/security`

| Span                                   | When                                   | Attributes                                                                       | Error status                                              |
| --------------------------------------- | --------------------------------------- | --------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `security.Engine.Process`               | `Engine.Process` — extract + authenticate | `security.extractors.count` (int), `security.authenticated` (bool)                | `ErrNoExtractor`, extractor error, or manager error        |
| `security.Manager.Authenticate`         | `Manager.Authenticate` — chain authenticators | `security.authenticators.count` (int), `security.authenticated` (bool, on success), `security.authenticator.name` (string, on success); event `authenticator.try` per candidate | `ErrUnsupportedCredential`, `ErrAuthenticatorRefused`      |
| `security.AccessDecisionManager.Decide` | `AccessDecisionManager.Decide`          | `security.strategy` (string), `security.attributes` (string, joined), `security.decision` (string) | `ErrAccessDenied` when the final decision is not Grant     |

`security.principal.subject` is a **reserved** attribute key. It is not
emitted by default — subject identifiers are PII and high-cardinality. Wire
it yourself only behind a deliberate, low-cardinality (hashed) opt-in.

### HTTP — `github.com/hyperscale-stack/security/http`

| Span                | When                          | Attributes                                                          | Error status            |
| ------------------- | ----------------------------- | -------------------------------------------------------------------- | ----------------------- |
| `httpsec.Middleware` | Per request through `Middleware` | `http.method` (string), `http.route` (string), `security.handled` (bool) | inherited from the core |

`httpsec.Middleware` is the parent span of the core `security.Engine.*`
spans for that request. `httpsec.Authorize` does **not** open its own span —
it delegates to `security.AccessDecisionManager.Decide`.

### gRPC — `github.com/hyperscale-stack/security/grpc`

| Span                   | When                                            | Attributes                                                  | Error status            |
| ---------------------- | ----------------------------------------------- | ------------------------------------------------------------ | ----------------------- |
| `grpcsec.Authenticate` | Per RPC, unary and stream interceptors          | `rpc.method` (string), `security.authenticated` (bool)       | inherited from the core |
| `grpcsec.Authorize`    | `UnaryAuthorize` / `StreamAuthorize`            | none directly — delegates to `security.AccessDecisionManager.Decide` | inherited from the core |

`grpcsec` deliberately does **not** open an `rpc` span — that belongs to
`otelgrpc`, which you compose alongside these interceptors.

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
| `jwtsec.Verifier.Verify` | `Verifier.Verify` | `jwt.alg` (string), `jwt.kid` (string), `jwt.iss` (string) | parse, multi-signature, disallowed alg, unknown kid, bad signature, malformed payload, claim validation |

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

## Secrets policy

No span attribute ever carries a secret: cleartext passwords, access or
refresh tokens, authorization codes, client secrets, or raw session IDs.
Where correlation is genuinely needed, the value is hashed first
(`session.id_hash`). When you add your own instrumentation around this
library, keep the same rule.

## Verifying spans in tests

The test suites use the OpenTelemetry SDK's in-memory exporter
(`tracetest.NewSpanRecorder`) to assert span names, attributes, and status.
Apply the same pattern in your own integration tests, or run any example
with `OTEL_TRACES_EXPORTER=console` to see the spans on stdout.
