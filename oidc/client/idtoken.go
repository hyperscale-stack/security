// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejson "github.com/go-jose/go-jose/v4/json"
)

// maxSubjectLength is the OpenID Connect Core §2 bound on sub.
const maxSubjectLength = 255

// maxNumericDate is 9999-12-31T23:59:59Z, the largest NumericDate the
// package accepts.
const maxNumericDate = 253402300799

// idTokenClaims holds the claims the Client validates; the whole claims
// set is returned in Identity.Claims.
type idTokenClaims struct {
	Issuer    string              `json:"iss"`
	Subject   string              `json:"sub"`
	Audience  josejson.RawMessage `json:"aud"`
	Expiry    josejson.RawMessage `json:"exp"`
	IssuedAt  josejson.RawMessage `json:"iat"`
	NotBefore josejson.RawMessage `json:"nbf"`
	AuthTime  josejson.RawMessage `json:"auth_time"`
	Nonce     string              `json:"nonce"`
	ACR       string              `json:"acr"`
	AMR       []string            `json:"amr"`
	AZP       *string             `json:"azp"`
	ATHash    *string             `json:"at_hash"`
}

// verifiedTimes are the time claims of a validated ID Token.
type verifiedTimes struct {
	issuedAt, expiresAt, authTime time.Time
}

// verifyLogin validates the ID Token of tokens and builds the Identity.
func (c *Client) verifyLogin(ctx context.Context, tokens Tokens, tx *Transaction, nonce string) (*Identity, error) {
	alg, payload, err := c.verifyIDToken(ctx, tokens.IDToken)
	if err != nil {
		return nil, err
	}

	var claims idTokenClaims
	if err := decodeStrict(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDTokenMalformed, err)
	}

	audience, err := c.checkParties(&claims)
	if err != nil {
		return nil, err
	}

	times, err := c.checkTimes(&claims, tx, c.now())
	if err != nil {
		return nil, err
	}

	if err := checkRequest(&claims, tx, nonce); err != nil {
		return nil, err
	}

	if claims.ATHash != nil && subtle.ConstantTimeCompare([]byte(*claims.ATHash), []byte(accessTokenHash(alg, tokens.AccessToken))) != 1 {
		return nil, ErrAccessTokenHash
	}

	return &Identity{
		ConnectionID: c.cfg.ConnectionID,
		Issuer:       claims.Issuer,
		Subject:      claims.Subject,
		Audience:     audience,
		AuthTime:     times.authTime,
		ACR:          claims.ACR,
		AMR:          claims.AMR,
		IssuedAt:     times.issuedAt,
		ExpiresAt:    times.expiresAt,
		Claims:       payload,
		Tokens:       tokens,
		AppState:     tx.AppState,
	}, nil
}

// verifyIDToken parses the JWS Compact Serialization (RFC 7515 §7.1) — JWE
// and the JSON serialization are refused — with the effective algorithm
// allow-list, checks its explicit type, and verifies the signature with a
// key of the issuer's JWK Set (never one named by jwk, jku, x5u or x5c).
func (c *Client) verifyIDToken(ctx context.Context, raw string) (Algorithm, []byte, error) {
	jws, err := jose.ParseSignedCompact(raw, c.joseAlgs)
	if err != nil {
		var algErr *jose.ErrUnexpectedSignatureAlgorithm
		if errors.As(err, &algErr) {
			return "", nil, ErrIDTokenAlgorithm
		}

		return "", nil, fmt.Errorf("%w: %w", ErrIDTokenMalformed, err)
	}

	header := jws.Signatures[0].Header
	if err := checkHeader(header); err != nil {
		return "", nil, err
	}

	alg := Algorithm(header.Algorithm)

	payload, err := c.verifySignature(ctx, jws, alg, header.KeyID)
	if err != nil {
		return "", nil, err
	}

	return alg, payload, nil
}

// checkHeader applies explicit typing (RFC 8725 §3.11-3.12): typ absent or
// JWT (RFC 7519 §5.1) — an RFC 9068 at+jwt access token or any other typed
// JWT is not an ID Token — no nested JWT (cty), no JWS extension (crit,
// b64).
func checkHeader(h jose.Header) error {
	if typ, ok := h.ExtraHeaders[jose.HeaderType]; ok {
		s, isString := typ.(string)
		if !isString || !strings.EqualFold(strings.TrimPrefix(strings.ToLower(s), "application/"), "jwt") {
			return fmt.Errorf("%w: typ is not JWT", ErrIDTokenType) // the value is attacker-chosen: never echoed
		}
	}

	for _, name := range []jose.HeaderKey{jose.HeaderContentType, "crit", "b64"} {
		if _, ok := h.ExtraHeaders[name]; ok {
			return fmt.Errorf("%w: header %s", ErrIDTokenType, name)
		}
	}

	return nil
}

// verification is the outcome of verifying with the candidate keys.
type verification int

const (
	verified verification = iota
	noKey
	ambiguousKey
	badSignature
)

// verifySignature verifies with the key designated by kid (or the single
// compatible key when there is no kid, OpenID Connect Core §10.1). An
// unknown kid, or a kid-less token no cached key verifies, triggers one
// rate-limited refresh of the set (§10.1.1); a bad signature under a known
// kid never does.
func (c *Client) verifySignature(ctx context.Context, jws *jose.JSONWebSignature, alg Algorithm, kid string) ([]byte, error) {
	keys, err := c.keys.current(ctx)
	if err != nil {
		return nil, err
	}

	payload, outcome := verifyWith(jws, candidates(keys, kid, alg, c.algs))

	switch {
	case outcome == verified:
		return payload, nil
	case outcome == ambiguousKey:
		return nil, fmt.Errorf("%w: several keys match, a kid is required", ErrUnknownSigningKey)
	case outcome == badSignature && kid != "":
		return nil, ErrIDTokenSignature
	}

	if _, err := c.keys.refresh(ctx); err != nil && ctx.Err() != nil {
		return nil, err
	}

	payload, outcome = verifyWith(jws, candidates(c.keys.snapshot(), kid, alg, c.algs))

	switch outcome {
	case verified:
		return payload, nil
	case badSignature:
		return nil, ErrIDTokenSignature
	case noKey, ambiguousKey:
	}

	return nil, ErrUnknownSigningKey
}

func verifyWith(jws *jose.JSONWebSignature, keys []verificationKey) ([]byte, verification) {
	switch len(keys) {
	case 0:
		return nil, noKey
	case 1:
	default:
		return nil, ambiguousKey
	}

	payload, err := jws.Verify(keys[0].key)
	if err != nil {
		return nil, badSignature
	}

	return payload, verified
}

// checkParties checks iss, sub, aud and azp (OpenID Connect Core §2,
// §3.1.3.7).
func (c *Client) checkParties(claims *idTokenClaims) ([]string, error) {
	if claims.Issuer != c.md.Issuer {
		return nil, ErrIDTokenIssuer
	}

	if !isASCII(claims.Subject, printableASCII, maxSubjectLength) {
		return nil, fmt.Errorf("%w: sub", ErrIDTokenMissingClaim)
	}

	audience, err := parseAudience(claims.Audience)
	if err != nil {
		return nil, err
	}

	if !slices.Contains(audience, c.cfg.ClientID) {
		return nil, fmt.Errorf("%w: the client is not an audience", ErrIDTokenAudience)
	}

	for _, aud := range audience {
		if aud != c.cfg.ClientID && !slices.Contains(c.cfg.TrustedAudiences, aud) {
			return nil, fmt.Errorf("%w: untrusted audience", ErrIDTokenAudience)
		}
	}

	// Errata set 2 encourages ignoring azp absent extensions; checking it
	// when present is the §3.1.3.7 option this package takes.
	if claims.AZP != nil && *claims.AZP != c.cfg.ClientID {
		return nil, ErrIDTokenAuthorizedParty
	}

	return audience, nil
}

// parseAudience reads aud: a string or an array of strings.
func parseAudience(raw josejson.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == jsonNull {
		return nil, nil
	}

	var one string
	if josejson.Unmarshal(raw, &one) == nil {
		return []string{one}, nil
	}

	var many []string
	if err := josejson.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("%w: aud: %w", ErrIDTokenMalformed, err)
	}

	return many, nil
}

// checkTimes checks exp (RFC 7519 §4.1.4), iat (in the past, and not
// before the authorization request: Core §3.1.3.7), nbf (RFC 7519 §4.1.5)
// and auth_time (Core §3.1.2.1 max_age), with the clock skew.
func (c *Client) checkTimes(claims *idTokenClaims, tx *Transaction, now time.Time) (verifiedTimes, error) {
	skew := c.cfg.ClockSkew

	exp, err := requiredDate(claims.Expiry, "exp")
	if err != nil {
		return verifiedTimes{}, err
	}

	if !now.Before(exp.Add(skew)) {
		return verifiedTimes{}, ErrIDTokenExpired
	}

	iat, err := requiredDate(claims.IssuedAt, "iat")
	if err != nil {
		return verifiedTimes{}, err
	}

	if iat.After(now.Add(skew)) || iat.Before(tx.CreatedAt.Add(-skew)) {
		return verifiedTimes{}, ErrIDTokenIssuedAt
	}

	nbf, hasNBF, err := numericDate(claims.NotBefore)
	if err != nil {
		return verifiedTimes{}, err
	}

	if hasNBF && now.Before(nbf.Add(-skew)) {
		return verifiedTimes{}, ErrIDTokenNotYetValid
	}

	authTime, err := c.checkAuthTime(claims.AuthTime, tx, now)
	if err != nil {
		return verifiedTimes{}, err
	}

	return verifiedTimes{issuedAt: iat, expiresAt: exp, authTime: authTime}, nil
}

// checkAuthTime requires auth_time when max_age was sent, no older than
// max_age before the request; when present it may not be in the future.
func (c *Client) checkAuthTime(raw josejson.RawMessage, tx *Transaction, now time.Time) (time.Time, error) {
	authTime, present, err := numericDate(raw)

	switch {
	case err != nil:
		return time.Time{}, err
	case !present && tx.MaxAge != NoMaxAge:
		return time.Time{}, fmt.Errorf("%w: auth_time is required with max_age", ErrIDTokenMissingClaim)
	case !present:
		return time.Time{}, nil
	case authTime.After(now.Add(c.cfg.ClockSkew)):
		return time.Time{}, fmt.Errorf("%w: auth_time in the future", ErrIDTokenAuthTime)
	case tx.MaxAge != NoMaxAge && authTime.Before(tx.CreatedAt.Add(-time.Duration(tx.MaxAge)*time.Second-c.cfg.ClockSkew)):
		return time.Time{}, ErrIDTokenAuthTime
	}

	return authTime, nil
}

// checkRequest checks the claims bound to the authorization request: the
// nonce (Core §3.1.3.7; it also defeats code injection, RFC 9700 §4.5.3.2)
// and, when acr_values were sent, the acr (decision D4).
func checkRequest(claims *idTokenClaims, tx *Transaction, nonce string) error {
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return ErrIDTokenNonce
	}

	if tx.ACRValues != "" && !slices.Contains(strings.Fields(tx.ACRValues), claims.ACR) {
		return ErrIDTokenACR
	}

	return nil
}

func requiredDate(raw josejson.RawMessage, name string) (time.Time, error) {
	t, present, err := numericDate(raw)
	if err != nil {
		return time.Time{}, err
	}

	if !present {
		return time.Time{}, fmt.Errorf("%w: %s", ErrIDTokenMissingClaim, name)
	}

	return t, nil
}

// numericDate reads an RFC 7519 §2 NumericDate: a JSON number of seconds,
// fractions allowed, between 0 and year 9999.
func numericDate(raw josejson.RawMessage) (time.Time, bool, error) {
	text := string(raw)
	if text == "" || text == jsonNull {
		return time.Time{}, false, nil
	}

	seconds, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(seconds) || seconds < 0 || seconds > maxNumericDate {
		return time.Time{}, false, fmt.Errorf("%w: NumericDate out of range", ErrIDTokenMalformed)
	}

	whole, frac := math.Modf(seconds)

	return time.Unix(int64(whole), int64(frac*float64(time.Second))).UTC(), true, nil
}

// accessTokenHash computes at_hash (Core §3.1.3.6): the left half of the
// hash of the access token with the hash of the signature algorithm —
// SHA-512 for EdDSA (Ed25519), as agreed by the OpenID Connect working
// group (issue #1125) and implemented by independent providers.
func accessTokenHash(alg Algorithm, accessToken string) string {
	h := sha256.New()

	switch alg {
	case RS384, PS384, ES384:
		h = sha512.New384()
	case RS512, PS512, ES512, EdDSA:
		h = sha512.New()
	case RS256, PS256, ES256:
	}

	h.Write([]byte(accessToken))
	sum := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}
