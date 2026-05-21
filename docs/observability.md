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
server's HTTP instrumentation (e.g. `otelhttp`).

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
