// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"time"
)

// FamilyRevocationRetention is the minimum time a [Storage] keeps a token
// family's revoked state after the revocation; it is never shorter than
// the expiry of any token of the family. It bounds a revocation recorded
// before the family's first token is issued.
const FamilyRevocationRetention = 24 * time.Hour

// MaxFamilyIDLength is the longest token-family identifier, in bytes, a
// [Storage] accepts: [TokenPair.Validate] and every RevokeRefreshFamily
// implementation refuse a longer one with invalid_request, so no backend
// can silently truncate two identifiers into the same family (the SQL
// store keeps them in a VARCHAR(64) column, VARBINARY(64) on MySQL).
const MaxFamilyIDLength = 64

// AuthorizationCodeStore persists single-use authorization codes (RFC 6749
// §4.1.2, §10.5). The grant consumes a code before validating it — see
// grant.AuthorizationCode for why — so the one atomic consumption is the
// single-use guarantee. A code is stored under its hash,
// [AuthorizationCode.CodeHash], which the issuer sets: implementations MUST
// NOT persist the raw [AuthorizationCode.Code]. Consuming a code does not
// delete it: the record is kept, flagged consumed, at least until its
// ExpiresAt, so that a replay can be told from an unknown code and the
// server can revoke what the first exchange issued. Afterwards an
// implementation MAY drop it — the Redis store expires the key, the SQL
// store documents a cleanup, the memory store keeps it for its lifetime.
type AuthorizationCodeStore interface {
	// SaveAuthorizationCode persists code under code.CodeHash; an empty
	// hash is rejected with invalid_request. Callers MUST save a given
	// CodeHash at most once: a store may overwrite the record, and
	// re-saving a consumed code can make it redeemable again (the Redis
	// store does).
	SaveAuthorizationCode(ctx context.Context, code *AuthorizationCode) error

	// ConsumeAuthorizationCode atomically marks the code codeHash consumed
	// and returns its record to AT MOST one caller, even under
	// concurrency. Every other call returns a nil code and an error:
	//
	//   - a [*CodeReplayError] carrying the retained record when the code
	//     was already consumed — every concurrent loser gets one. The
	//     record only lets the caller revoke what the first exchange
	//     issued: it MUST NOT be used to issue tokens;
	//   - [ErrCodeAlreadyUsed] when the code is unknown: never saved, or
	//     no longer retained;
	//   - a wrapped error on a backend failure.
	//
	// Both refusals match [ErrCodeAlreadyUsed] (invalid_grant). A decorator
	// or wrapper MUST return the store's error unchanged or wrapped with
	// %w: normalizing it to ErrCodeAlreadyUsed silently disables the
	// revocation a replay triggers. Expiry is not checked: the caller
	// compares ExpiresAt with its own clock.
	ConsumeAuthorizationCode(ctx context.Context, codeHash string) (*AuthorizationCode, error)
}

// AccessTokenStore is the access-token view of a [Storage] — the part a
// resource server validating opaque tokens needs. It is a consumer view,
// not a separately implementable half: see [Storage]. Implementations MUST
// store hashes (the canonical hash function is [HashToken]).
type AccessTokenStore interface {
	// LookupAccessToken returns the token record matching tokenHash, or
	// nil + an invalid_grant [*Error] when none matches or when the
	// token's family is revoked. Tokens outside any family are never
	// affected by family revocation.
	LookupAccessToken(ctx context.Context, tokenHash string) (*AccessToken, error)
	// RevokeAccessToken deletes the token matching tokenHash. Revoking an
	// unknown token is a no-op.
	RevokeAccessToken(ctx context.Context, tokenHash string) error
}

// RefreshTokenStore is the refresh-token view of a [Storage]. It is a
// consumer view, not a separately implementable half: see [Storage].
type RefreshTokenStore interface {
	// LookupRefreshToken returns the refresh-token record matching
	// tokenHash, or nil + an invalid_grant [*Error] when none matches. A
	// rotated token, or a token of a revoked family, comes back with
	// Consumed=true: the caller treats presenting it as reuse.
	LookupRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	// RotateRefreshToken atomically consumes the refresh token oldHash and
	// persists next — an access token and a refresh token, both in
	// oldHash's family and carrying its grant context (Issuer and
	// ExtensionData, unchanged) — or changes nothing (I3).
	//
	// A malformed next — nil, without a refresh token, or failing
	// [TokenPair.Validate] — is refused with invalid_request before
	// anything is read. The other errors come in this order: invalid_grant
	// when oldHash is unknown; invalid_request when next declares another
	// family than oldHash's, or another Issuer or ExtensionData — a
	// rotation never re-binds a grant to another realm nor rewrites the
	// authentication event it rests on; [ErrTokenFamilyRevoked] when the
	// family is revoked; [ErrRefreshTokenReused] when oldHash was already
	// consumed.
	// On reuse the family is revoked before the return; when that
	// revocation fails, the error also wraps [ErrTokenFamilyRevocationFailed]
	// and its cause, and the family MUST be treated as active (I4). Callers
	// therefore test errors.Is(err, ErrTokenFamilyRevocationFailed)
	// themselves: the OAuth2 code stays invalid_grant either way.
	//
	// Retrying a rotation that was already applied, with the identical
	// next, MAY succeed: callers always pass a freshly generated next.
	RotateRefreshToken(ctx context.Context, oldHash string, next *TokenPair) error
	// RevokeRefreshFamily records familyID as revoked — even when no token
	// of the family exists yet — so that I1 and I2 hold once it returns
	// nil. It is idempotent (I5). A failure wraps
	// [ErrTokenFamilyRevocationFailed]; its outcome may be unknown, so the
	// caller treats the family as active and retries (I6). An empty ID, or
	// one longer than [MaxFamilyIDLength], is rejected with invalid_request
	// (I7).
	RevokeRefreshFamily(ctx context.Context, familyID string) error
}

// Storage is the persistence contract of the authorization server.
//
// The token operations — [AccessTokenStore], [RefreshTokenStore] and
// SaveTokenPair — MUST share one backend: SaveTokenPair and
// RotateRefreshToken write access and refresh tokens atomically, and every
// lookup consults the same token-family state. AccessTokenStore and
// RefreshTokenStore are consumer views, not halves that may be implemented
// on different backends; only the [AuthorizationCodeStore] may live
// elsewhere. [ServerConfig.Storage] and the Storage of every grant MUST be
// the same store.
//
// # Token families
//
// The access and refresh tokens issued from one authorization share a
// non-empty FamilyID: they form a family. client_credentials and implicit
// access tokens belong to none and are never affected by a family
// revocation. A store keeps one authoritative state per family — active
// or revoked — and serializes every write into the family on it, so a
// revocation never has to find and purge tokens: lookups honor the state.
//
// A revocation R of family F is complete once RevokeRefreshFamily(F)
// returned nil, or once a RotateRefreshToken reporting reuse returned an
// error that does not match [ErrTokenFamilyRevocationFailed]. "After R"
// means invoked after R returned, while F is retained:
//
//   - I1, visibility: after R, LookupAccessToken fails with invalid_grant
//     for every access token of F, and LookupRefreshToken returns every
//     refresh token of F with Consumed set (or fails with invalid_grant).
//   - I2, gating: every SaveTokenPair or RotateRefreshToken into F is
//     ordered either before R — I1 then covers its tokens — or after it,
//     failing with [ErrTokenFamilyRevoked] (or [ErrRefreshTokenReused] for
//     a consumed token) without persisting anything. A lookup concurrent
//     with R may still see F active: it is ordered before R.
//   - I3, atomic writes: SaveTokenPair and RotateRefreshToken apply all
//     their writes or none. A failed call persists no token and consumes
//     nothing; the one exception is reuse, which only records F as
//     revoked.
//   - I4, reuse: RotateRefreshToken on a consumed token of a non-revoked
//     family fails with [ErrRefreshTokenReused]; one of an already revoked
//     family may fail with [ErrTokenFamilyRevoked] instead (both are
//     invalid_grant). Unless the error also matches
//     [ErrTokenFamilyRevocationFailed], F was revoked before the return;
//     otherwise it also wraps the cause, and F MUST be treated as active.
//   - I5, idempotence and monotonicity: a revoked family never becomes
//     active again, and revoking it again returns nil and changes nothing
//     observable. F is retained at least until every token of F has
//     expired and for [FamilyRevocationRetention] after its first
//     revocation, so a revocation recorded before the first issuance still
//     refuses it.
//   - I6, failure: RevokeRefreshFamily returns nil or an error wrapping
//     [ErrTokenFamilyRevocationFailed] (invalid_request for an empty or
//     over-long ID, I7). A failed call applies nothing, but its outcome
//     can be unknown (a lost acknowledgement): the caller treats F as
//     active and retries, which I5 makes safe.
//   - I7, isolation: nothing done to F affects another family or a token
//     outside any family; RevokeRefreshFamily("") is rejected.
//   - I8, fail closed: a store that can lose family state (expiry,
//     eviction, cleanup) treats a token whose family it no longer knows as
//     a token of a revoked family. This protects lookups only: the next
//     issuance into a family whose revoked state was lost records it
//     active again, reviving its tokens, so a store MUST NOT lose a
//     revoked family's state within its retention (I5).
//
// The authorization_code grant derives the family of the tokens a code
// issues from the code hash, before consuming the code. A replay of the
// code that proves possession revokes that family: by I1 and I2, the
// tokens the code issued stop working, and an exchange of the code still
// in flight fails instead of issuing — one more reason a store MUST keep a
// revoked family's state for its whole retention (I5, I8).
//
// # Grant context
//
// Codes and tokens carry the Issuer they were issued under and the opaque
// ExtensionData an [Extension] recorded for their authorization. A store
// persists both byte-exact — valid UTF-8 without NUL, at most
// [MaxExtensionDataLength] bytes of ExtensionData — and returns them from
// every read: ConsumeAuthorizationCode and the record of a
// [*CodeReplayError], LookupAccessToken, LookupRefreshToken, a consumed
// refresh token included. A record written before these fields existed
// reads them as "". RotateRefreshToken refuses a replacement that changes
// them.
//
// A store returns the sentinels themselves or wraps them with %w: an
// [*Error] has no Is method, so a WithDescription or WithCause copy no
// longer matches its sentinel. Every implementation MUST pass the shared
// oauth2/storetest conformance suite.
type Storage interface {
	AuthorizationCodeStore
	AccessTokenStore
	RefreshTokenStore

	// SaveTokenPair atomically persists a newly issued pair: both tokens
	// or neither (I3). A pair whose access token carries a FamilyID joins
	// that family, creating it when unknown, and fails with
	// [ErrTokenFamilyRevoked] once the family is revoked (I2); a pair
	// outside any family carries no refresh token and is never gated. A
	// pair failing [TokenPair.Validate] is refused with invalid_request.
	SaveTokenPair(ctx context.Context, pair *TokenPair) error
}
