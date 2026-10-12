// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
)

// Scope values (OpenID Connect Core §3.1.2.1, §5.4, §11).
const (
	// ScopeOpenID makes an authorization request an OpenID Connect
	// authentication request (Core §3.1.2.1).
	ScopeOpenID = "openid"
	// ScopeProfile requests the default profile claims at UserInfo.
	ScopeProfile = "profile"
	// ScopeEmail requests email and email_verified at UserInfo.
	ScopeEmail = "email"
	// ScopeAddress requests address at UserInfo.
	ScopeAddress = "address"
	// ScopePhone requests phone_number and phone_number_verified at UserInfo.
	ScopePhone = "phone"
	// ScopeOfflineAccess requests a refresh token enabling access while the
	// end-user is absent (Core §11): wire grant.Config.RefreshTokenScope to
	// it, and grant it only with the end-user's consent
	// ([Decision].OfflineAccess). The provider drops it from every grant —
	// OpenID or plain OAuth 2.0 — the decision does not grant it. Only the
	// scope is gated: the refresh tokens of a plain OAuth 2.0 grant, which
	// carries no provider context, follow RefreshTokenScope alone (Core §11
	// "other contexts").
	ScopeOfflineAccess = "offline_access"
)

// ClaimsSource supplies end-user claims. The provider asks it for the
// claims of an ID Token — at the code exchange and at every refresh — and
// of a UserInfo response, naming in [ClaimsQuery].Names the only claims it
// may release; whatever else the source returns is dropped, and so are
// null and empty-string values (Core §5.3.2) and the protocol claims the
// provider sets itself (sub, iss, aud, exp, iat, auth_time, nonce, acr,
// amr, at_hash, …) — a source cannot override them.
//
// Claim names are case-sensitive (Core §5.1, RFC 7519 §4), but relying
// parties often match them case-insensitively — Go's encoding/json reads
// "SUB" or "ſub" as sub, the last one winning — or normalize them
// ("email.verified" to emailVerified). Under that comparison (a "case
// variant": the same name ignoring case — simple and full case mappings —,
// every ASCII character but letters, digits and "#", and Unicode white
// space), the provider never releases, and never asks for:
//   - a case variant of a protocol claim, or of a claim reserved to another
//     protocol (azp, jti, sid, scope, …);
//   - a case variant of a claim it knows — the standard claims of Core
//     §5.1, roles, groups and entitlements (RFC 9068 §2.2.3.1) and
//     [Config].ClaimsSupported — other than its exact spelling ("Email",
//     "e_mail", "EMAIL#fr" are dropped, "email#fr" is released).
//
// Of what remains, it drops every claim whose name is a case variant of
// another one released with it (all of them: which one a relying party
// would read is unknowable), whose name is not 1 to 255 bytes of UTF-8
// without control characters, and whose value holds, at any depth, an
// object with two member names that are case variants of each other
// (exact duplicates included) or a member name in invalid UTF-8 or with a
// control character, an unpaired surrogate escape or a number beyond
// float64, or is nested more than 31 levels — relying parties refuse a
// whole token or document holding one. Dropping a claim is never an error
// (Core §5.3.2, §5.5); a value encoding/json cannot encode answers
// server_error.
//
// A source whose claim names end-users or upstream directories choose
// must keep them apart from the names relying parties consume, and
// declare its own claims in Config.ClaimsSupported: an undeclared claim
// is still released under another spelling when requested alone (a
// relying party may read it as the claim it expects), and is dropped when
// requested together with such a variant (an end-user can suppress it).
// Member names inside structured values (address) are the source's.
//
// The provider queries it on every token exchange of an OpenID grant, an
// ID Token being issued or not: returning [ErrUnknownSubject] for an
// end-user that no longer exists or may no longer sign in stops the grant
// (invalid_grant, invalid_token at UserInfo). Any other error answers
// server_error. Implementations MUST be safe for concurrent use.
type ClaimsSource interface {
	Claims(ctx context.Context, q ClaimsQuery) (map[string]any, error)
}

// ClaimsTarget tells where the claims of a [ClaimsQuery] go.
type ClaimsTarget string

const (
	// ClaimsForIDToken targets an ID Token — or, with no Names, only checks
	// that the end-user is still valid (a refresh issuing no ID Token).
	ClaimsForIDToken ClaimsTarget = "id_token"
	// ClaimsForUserInfo targets a UserInfo response.
	ClaimsForUserInfo ClaimsTarget = "userinfo"
)

// ClaimsQuery asks a [ClaimsSource] for the claims of one end-user.
type ClaimsQuery struct {
	// Issuer is the realm the end-user belongs to.
	Issuer string
	// Subject is the end-user's sub within Issuer.
	Subject string
	// ClientID is the client the claims are released to.
	ClientID string
	// Target is where the claims go.
	Target ClaimsTarget
	// Names lists the claims the provider may release: those of the granted
	// scopes (UserInfo) and those the end-user agreed to release through the
	// claims parameter. A language-tagged variant of a listed name
	// ("name#fr", Core §5.2) is released with it. Empty: release nothing.
	// The claims parameter's names are chosen by the client: untrusted
	// input, only known to be 1 to 255 bytes of UTF-8 without control
	// characters and releasable (see [ClaimsSource]) — a source that looks
	// them up in a directory or a database escapes or parameterizes them,
	// or maps them through its own list.
	Names []string
}

// Claim names the provider handles itself (OpenID Connect Core §2, §3.1.3.6).
const (
	claimIss      = "iss"
	claimSub      = "sub"
	claimAud      = "aud"
	claimExp      = "exp"
	claimIat      = "iat"
	claimAuthTime = "auth_time"
	claimNonce    = "nonce"
	claimACR      = "acr"
	claimAMR      = "amr"
	claimAtHash   = "at_hash"
	claimScope    = "scope"
)

// reservedClaims are the claims the provider sets itself, or that belong to
// another protocol: a ClaimsSource never supplies them nor their case
// variants, whatever it returns, and the provider never asks for them.
var reservedClaims = []string{
	claimIss, claimSub, claimAud, claimExp, claimIat, "nbf", "jti", claimAuthTime, claimNonce, claimACR, claimAMR, "azp",
	claimAtHash, "c_hash", "s_hash", "sid", "cnf", claimScope, "client_id", "typ", "_claim_names", "_claim_sources",
}

// reservedKeys are the claimKeys of the reserved claims.
var reservedKeys = keySet(reservedClaims)

// scopeClaims are the claims each scope value requests from UserInfo (Core
// §5.4).
var scopeClaims = map[string][]string{
	ScopeProfile: {
		"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile",
		"picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
	},
	ScopeEmail:   {"email", "email_verified"},
	ScopeAddress: {"address"},
	ScopePhone:   {"phone_number", "phone_number_verified"},
}

// reserved reports whether the untagged claim name base is a reserved
// claim or a case variant of one: "SUB" and "ſub" are sub.
func reserved(base string) bool {
	_, ok := reservedKeys[claimKey(base)]

	return ok
}

// releaseSet maps the names a response may release to their acceptable
// values (none: any value): the claims of scopes, then the released claim
// requests the provider may release (see claimNames.releasable), whose
// value constraints apply.
func (n claimNames) releaseSet(requested []storedClaim, scopes []string) map[string][]json.RawMessage {
	out := map[string][]json.RawMessage{}

	for _, scope := range scopes {
		for _, name := range scopeClaims[scope] {
			out[name] = nil
		}
	}

	for _, c := range requested {
		if n.releasable(c.Name) {
			out[c.Name] = c.Values
		}
	}

	return out
}

// queryNames lists the names of a release set, sorted.
func queryNames(allowed map[string][]json.RawMessage) []string {
	names := make([]string, 0, len(allowed))
	for name := range allowed {
		names = append(names, name)
	}

	slices.Sort(names)

	return names
}

// errClaimValue reports a ClaimsSource value encoding/json cannot encode;
// it carries neither the value nor its name.
var errClaimValue = errors.New("oidcprovider: claims source: a released claim value cannot be encoded as JSON")

// releaseClaims keeps, of what a ClaimsSource returned, the claims allowed
// lists — a language-tagged variant ("name#fr") with its untagged name —
// under a valid claim name, encoded: their value is neither null nor an
// empty string (Core §5.3.2), matches the request's value constraint, if
// any (Core §5.5.1), and is well formed (see wellFormedValue). It then
// drops every name that is a case variant of another kept one. allowed
// never holds a reserved claim (see claimNames.releaseSet), so none is ever
// kept. A value encoding/json cannot encode fails with errClaimValue —
// unless constrained: it then matches no value and is dropped.
func releaseClaims(src map[string]any, allowed map[string][]json.RawMessage) (map[string]any, error) {
	out := make(map[string]any, len(src))

	for name, v := range src {
		values, ok := allowedValues(allowed, name)
		if !ok || !validClaimName(name) {
			continue
		}

		encoded, err := json.Marshal(v)

		switch {
		case err != nil && len(values) > 0:
			continue
		case err != nil:
			return nil, errClaimValue
		case omitted(encoded), len(values) > 0 && !matchesAny(encoded, values), !wellFormedValue(encoded):
			continue
		}

		out[name] = json.RawMessage(encoded)
	}

	dropCaseVariants(out)

	return out, nil
}

// allowedValues returns the acceptable values of name in allowed — or of
// its untagged name — and whether either is allowed.
func allowedValues(allowed map[string][]json.RawMessage, name string) ([]json.RawMessage, bool) {
	if values, ok := allowed[name]; ok {
		return values, true
	}

	values, ok := allowed[untagged(name)]

	return values, ok
}

// jsonNull is the JSON null literal.
const jsonNull = "null"

// omitted reports an encoded null or empty string: never released (Core
// §5.3.2: "SHOULD NOT be present with a null or empty string value").
func omitted(encoded []byte) bool {
	return string(encoded) == jsonNull || string(encoded) == `""`
}

// dropCaseVariants deletes every claim whose name is a case variant of
// another one's (see claimKey).
func dropCaseVariants(claims map[string]any) {
	count := make(map[string]int, len(claims))
	for name := range claims {
		count[claimKey(name)]++
	}

	for name := range claims {
		if count[claimKey(name)] > 1 {
			delete(claims, name)
		}
	}
}

// matchesAny reports whether the encoded claim value equals one of values —
// an equality of JSON scalars (Core §5.5.1, §14): strings code point by
// code point, booleans, numbers numerically. An object or array matches
// nothing.
func matchesAny(encoded []byte, values []json.RawMessage) bool {
	got, ok := scalarOf(encoded)
	if !ok {
		return false
	}

	for _, raw := range values {
		if want, ok := scalarOf(raw); ok && want == got {
			return true
		}
	}

	return false
}

// scalarOf decodes a JSON scalar to a comparable value — a string, a bool
// or a finite float64 — or reports false: a number beyond float64 is no
// value (strconv.ParseFloat answers ±Inf with ErrRange, and JSON has no
// other infinite literal).
func scalarOf(raw []byte) (any, bool) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}

	switch x := v.(type) {
	case string, bool:
		return x, true
	case json.Number:
		f, err := strconv.ParseFloat(x.String(), 64)
		if err != nil {
			return nil, false
		}

		return f, true
	default:
		return nil, false
	}
}
