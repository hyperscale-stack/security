// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package jwtsec provides JWT signing and verification with JWKS support and
// key rotation, usable standalone (as a Bearer TokenVerifier) or as the
// signer behind the OAuth2 server's JWT access-token format.
//
// Security defaults:
//   - "alg=none" is rejected unconditionally.
//   - The allowed-algorithm list defaults to the asymmetric schemes
//     (RSA, RSA-PSS, ECDSA, EdDSA); HMAC algorithms are accepted only on
//     explicit opt-in via WithAllowedAlgorithms, to avoid key confusion. An
//     algorithm outside the list is refused with ErrAlgorithmNotAllowed.
//   - Parsing is bounded and strict: a token over DefaultMaxTokenSize
//     (16 KiB, WithMaxTokenSize) is refused before any decoding; only the
//     canonical compact serialization is accepted (unpadded base64url, no
//     whitespace, zero pad bits); the header is strict JSON and may not use
//     the crit or b64 extensions (RFC 7515 §4.1.11, RFC 7797) nor the jwk,
//     x5c, jku or x5u members, refused before go-jose parses the header —
//     a local policy: keys come from the configured key set only (RFC 9068
//     §4, RFC 8725 §3.10); values taken from a token are clipped in errors
//     and spans.
//   - Claims are decoded case-sensitively (RFC 7519 §7.3, §10.1.1): a claims
//     set whose member names repeat — exactly, through an escape, or under
//     Unicode case folding — at any depth is refused, as are invalid UTF-8,
//     unpaired surrogate escapes, a payload that is not a JSON object, and a
//     registered claim of the wrong JSON type (null included). claimsOut is
//     decoded the same way, by go-jose's case-sensitive decoder.
//   - Every verification key is bound to one algorithm (RFC 8725 §3.1): its
//     Algorithm must equal the token's alg, an asymmetric key must pass
//     PublicKey.Validate (RSA of 2048 bits or more, the algorithm's curve, a
//     canonical Ed25519 point not of small order, a public key) and an HMAC
//     key must be a []byte secret. A kid shared by several keys designates
//     none.
//   - exp is required by default (WithOptionalExpiry); a token is expired
//     from now == exp + skew on; NumericDates outside 1970..9999 are
//     refused when reading and when signing; WithClockSkew is bounded by
//     MaxClockSkew (5 minutes).
//   - Issuer, audience and type checks are opt-in on NewVerifier
//     (WithIssuer, WithAudience, WithType) and mandatory for BearerVerifier,
//     the RFC 9068 §4 resource-server adapter: it refuses a verifier
//     without them; WithAccessTokenType names another required typ. Its
//     principal, an AccessTokenPrincipal, carries client_id:
//     SubjectIsClient tells a client_credentials token from a resource
//     owner's (RFC 9700 §4.15) — to refuse, never to grant.
//     WithActiveTokenCheck makes it ask the authorization server whether a
//     verified token is still active (RFC 7009 §3): ErrTokenInactive
//     otherwise.
//   - NewRemoteJWKS fetches through the SSRF-safe outbound client (https,
//     public destinations, no redirect, no proxy; the redirects a policy or
//     an opt-out client allows stay on the JWK Set URL's origin), refreshes
//     once per TTL in the background and once on an unknown kid — at most
//     once per MinKeySetRefreshInterval, one fetch shared by all callers,
//     never under a lock — stops using a set older than MaxKeySetStaleness,
//     ignores unusable keys one by one, and reports an outage as
//     ErrKeySetUnavailable — a security.ErrUnavailable, which the
//     transports answer with 503 / Unavailable — never as an invalid token.
//   - MarshalJWKS publishes a JWK Set of public signature keys and refuses
//     private or symmetric material and RSA keys over 4096 bits (go-jose ≥
//     v4.1.6's JSONWebKeySet refuses a whole set holding one);
//     PublicKey.Validate and
//     PrivateKey.Validate bind every key to one algorithm (RFC 8725 §3.1,
//     RFC 7518 key sizes and curves). NewSigner refuses a key that cannot
//     sign with its algorithm — KMS and HSM keys (jose.OpaqueSigner) are
//     checked through their public half, and an opaque PS* signer at each
//     signature: RSASSA-PSS salts are the hash size (RFC 7518 §3.5), as
//     every verifier requires — and NewOAuth2AccessTokenSigner
//     refuses claims missing an RFC 9068 §2.2 REQUIRED value.
//   - VerifySignature checks a signature and nothing else, for callers that
//     validate claims under their own rules (e.g. an OpenID Provider's
//     id_token_hint); Verifier is the general entry point.
//   - Explicit typing (RFC 8725 §3.11): signers write a "typ" header —
//     "JWT" by default, "at+jwt" for the RFC 9068 access tokens of
//     NewOAuth2AccessTokenSigner — and WithType makes a verifier require one.
//   - Key material is never printed: keys, signers, key sets and verifiers
//     print (every fmt verb), log (slog) and JSON-encode key IDs,
//     algorithms and key types only; a PublicKey JSON-encodes the public
//     fields of a public asymmetric key and nothing else; the remote
//     provider prints its URL without userinfo or query.
//   - Token strings are not unique: an ECDSA signature has a second valid
//     form, so never key a cache, replay or deny-list on the token string —
//     use jti.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core, outbound included)
//   - github.com/hyperscale-stack/security/bearer (TokenVerifier adapter)
//   - github.com/hyperscale-stack/security/oauth2 (access-token signer adapter)
//   - github.com/go-jose/go-jose/v4 (JOSE primitives)
//   - go.opentelemetry.io/otel
//   - stdlib only
package jwtsec
