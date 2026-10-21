// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	josejson "github.com/go-jose/go-jose/v4/json"
)

// Token response bounds.
const (
	maxIDTokenSize  = 64 << 10
	maxTokenLength  = 64 << 10
	maxExpiresIn    = 1<<31 - 1
	tokenTypeBearer = "Bearer"
	formContentType = "application/x-www-form-urlencoded"
)

// tokenResponse holds the members of a token response the Client uses
// (RFC 6749 §5.1, OpenID Connect Core §3.1.3.3).
type tokenResponse struct {
	AccessToken  string              `json:"access_token"`
	TokenType    string              `json:"token_type"`
	IDToken      string              `json:"id_token"`
	RefreshToken string              `json:"refresh_token"`
	ExpiresIn    josejson.RawMessage `json:"expires_in"`
	Scope        josejson.RawMessage `json:"scope"`
}

// tokenErrorResponse is an RFC 6749 §5.2 error response.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

// exchange redeems code at the token endpoint (RFC 6749 §4.1.3) with the
// PKCE verifier (RFC 7636 §4.5), authenticating as configured (OpenID
// Connect Core §9). The request never follows a redirect: it carries the
// code, the verifier and the client credentials.
func (c *Client) exchange(ctx context.Context, code, verifier string) (Tokens, error) {
	form := url.Values{
		paramGrantType:    {grantAuthorizationCode},
		paramCode:         {code},
		paramRedirectURI:  {c.cfg.RedirectURL},
		paramCodeVerifier: {verifier},
	}

	switch c.cfg.AuthMethod {
	case AuthMethodClientSecretPost:
		form.Set(paramClientID, c.cfg.ClientID)
		form.Set(paramClientSecret, c.cfg.ClientSecret.Reveal())
	case AuthMethodNone:
		form.Set(paramClientID, c.cfg.ClientID)
	case AuthMethodClientSecretBasic:
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.md.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: %w", ErrTokenEndpoint, err)
	}

	req.Header.Set("Content-Type", formContentType)
	req.Header.Set("Accept", mediaJSON)

	if c.cfg.AuthMethod == AuthMethodClientSecretBasic {
		// RFC 6749 §2.3.1: identifier and secret are form-urlencoded
		// (Appendix B) before the Basic encoding.
		req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret.Reveal()))
	}

	resp, err := c.send.Do(req) //nolint:gosec // G107/G704: endpoint from validated metadata, outbound policy enforced
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: %w", ErrTokenEndpoint, clipped(err)) // a refused redirect names its Location
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: read response: %w", ErrTokenEndpoint, clipped(err)) // a GOAWAY quotes its debug data
	}

	if resp.StatusCode != http.StatusOK {
		return Tokens{}, tokenFailure(resp, body)
	}

	if !hasMediaType(resp.Header.Get("Content-Type"), mediaJSON) {
		return Tokens{}, fmt.Errorf("%w: content type %s", ErrInvalidTokenResponse, quoted(resp.Header.Get("Content-Type")))
	}

	return parseTokenResponse(body, c.now())
}

// tokenFailure turns a non-200 token response into an error: a
// *TokenError for a well-formed RFC 6749 §5.2 error (400, or 401 for
// invalid_client), ErrTokenEndpoint otherwise. Descriptions and URIs outside
// their charsets are dropped.
func tokenFailure(resp *http.Response, body []byte) error {
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("%w: unexpected status %d", ErrTokenEndpoint, resp.StatusCode)
	}

	var e tokenErrorResponse
	if !hasMediaType(resp.Header.Get("Content-Type"), mediaJSON) || decodeStrict(body, &e) != nil || !isErrorText(e.Error, maxErrorCodeLength) {
		return fmt.Errorf("%w: unexpected status %d", ErrTokenEndpoint, resp.StatusCode)
	}

	tokenErr := &TokenError{StatusCode: resp.StatusCode, Code: e.Error}

	if isErrorText(e.ErrorDescription, maxErrorDescriptionLength) {
		tokenErr.Description = e.ErrorDescription
	}

	if isErrorURI(e.ErrorURI) {
		tokenErr.URI = e.ErrorURI
	}

	return tokenErr
}

// parseTokenResponse validates a successful token response strictly:
// access_token (1*VSCHAR) and id_token REQUIRED, token_type Bearer
// (case-insensitive; other token types are not supported), expires_in a
// non-negative integer (a decimal string is accepted for Microsoft Entra ID
// v1), refresh_token 1*VSCHAR when present. scope is informational: kept
// when it is a string, ignored otherwise.
func parseTokenResponse(body []byte, now time.Time) (Tokens, error) {
	var r tokenResponse
	if err := decodeStrict(body, &r); err != nil {
		return Tokens{}, fmt.Errorf("%w: %w", ErrInvalidTokenResponse, err)
	}

	switch {
	case !isASCII(r.AccessToken, printableASCII, maxTokenLength):
		return Tokens{}, fmt.Errorf("%w: missing or malformed access_token", ErrInvalidTokenResponse)
	case !strings.EqualFold(r.TokenType, tokenTypeBearer):
		return Tokens{}, fmt.Errorf("%w: token_type must be Bearer", ErrInvalidTokenResponse)
	case r.IDToken == "" || len(r.IDToken) > maxIDTokenSize:
		return Tokens{}, fmt.Errorf("%w: missing or oversized id_token", ErrInvalidTokenResponse)
	case r.RefreshToken != "" && !isASCII(r.RefreshToken, printableASCII, maxTokenLength):
		return Tokens{}, fmt.Errorf("%w: malformed refresh_token", ErrInvalidTokenResponse)
	}

	tokens := Tokens{
		AccessToken:  NewSecret(r.AccessToken),
		TokenType:    r.TokenType,
		RefreshToken: NewSecret(r.RefreshToken),
		IDToken:      NewSecret(r.IDToken),
	}

	seconds, present, err := parseExpiresIn(r.ExpiresIn)
	if err != nil {
		return Tokens{}, err
	}

	if present {
		tokens.Expiry = now.Add(time.Duration(seconds) * time.Second)
	}

	var scope string
	if josejson.Unmarshal(r.Scope, &scope) == nil {
		tokens.Scope = scope
	}

	return tokens, nil
}

// parseExpiresIn reads expires_in: a JSON integer, or a string of decimal
// digits, between 0 and 2^31-1.
func parseExpiresIn(raw josejson.RawMessage) (int64, bool, error) {
	text := string(raw)
	if text == "" || text == jsonNull {
		return 0, false, nil
	}

	if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
		text = text[1 : len(text)-1]
	}

	for i := range len(text) {
		if text[i] < '0' || text[i] > '9' {
			return 0, false, fmt.Errorf("%w: expires_in must be a non-negative integer", ErrInvalidTokenResponse)
		}
	}

	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n > maxExpiresIn {
		return 0, false, fmt.Errorf("%w: expires_in out of range", ErrInvalidTokenResponse)
	}

	return n, true, nil
}
