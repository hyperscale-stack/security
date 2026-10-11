// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hyperscale-stack/security/oauth2/pkce"
)

// Authorization-endpoint defaults applied when the matching
// [AuthorizeConfig] field is left zero.
const (
	// defaultAuthCodeTTL caps the authorization-code lifetime (RFC 6749
	// §4.1.2 recommends 10 minutes maximum).
	defaultAuthCodeTTL = 10 * time.Minute
	// defaultImplicitTTL is the implicit-flow access-token lifetime.
	defaultImplicitTTL = time.Hour
)

// RFC 6749 §3.1.1 response_type values handled by the authorization
// endpoint: "code" is the authorization-code flow, "token" the legacy
// implicit flow.
const (
	responseTypeCode  = "code"
	responseTypeToken = "token"
)

// The response_mode values of the response types above (OAuth 2.0
// Multiple Response Type Encoding Practices §2.1).
const (
	responseModeQuery    = "query"
	responseModeFragment = "fragment"
)

// authorizeFlow identifies which /authorize flow a request runs.
type authorizeFlow int

const (
	flowCode     authorizeFlow = iota // response_type=code
	flowImplicit                      // response_type=token (legacy)
)

// OpaqueTokenGenerator mints opaque tokens — a raw value plus the storage
// hash. The token sub-package's OpaqueRefreshAdapter and OpaqueCodeAdapter
// satisfy it; it is the type the implicit flow uses to issue access tokens.
type OpaqueTokenGenerator interface {
	Generate(ctx context.Context) (raw, hash string, err error)
}

// AuthorizeRequest is the parsed and validated /authorize request handed to
// a [ConsentFunc]. By the time the ConsentFunc sees it, the client, the
// redirect URI, the response type, the scope and the PKCE parameters are
// verified and the issuer is resolved. It is a copy: the handler keeps the
// request it validated, so changing it changes neither the redirect nor
// what is granted.
type AuthorizeRequest struct {
	// Client is the resolved, registered client.
	Client Client
	// ResponseType is the requested response type ("code" or "token").
	ResponseType string
	// RedirectURI is the validated redirect URI (exact-matched against the
	// client registration).
	RedirectURI string
	// Scope is the requested scope, already checked against the client's
	// allowed scopes.
	Scope string
	// State is the opaque client state echoed back on the redirect.
	State string
	// CodeChallenge / CodeChallengeMethod carry the PKCE parameters
	// (RFC 7636). Empty when the request carries no PKCE; unused by the
	// implicit flow. For the code flow they are validated before the
	// ConsentFunc runs: the method is allowed by the profile and the
	// challenge is well-formed for it (RFC 7636 §4.2).
	CodeChallenge       string
	CodeChallengeMethod string
	// Nonce echoes the OIDC nonce parameter, when present.
	Nonce string
	// Issuer is the issuer the IssuerResolver returned for the request: the
	// realm the authorization code — or implicit access token — is bound
	// to. A ConsentFunc authenticates the resource owner within it: a
	// session established at another issuer is no authentication here.
	Issuer string
}

// Consent is the resource-owner decision returned by a [ConsentFunc].
type Consent struct {
	// Approved reports whether the resource owner granted the request.
	Approved bool
	// Subject is the authenticated resource-owner identifier. It is
	// required when Approved is true.
	Subject string
	// Scope is the granted scope. Empty means "exactly what was requested";
	// a non-empty value MUST be a subset of [AuthorizeRequest.Scope] — the
	// consent step may narrow the grant but never broaden it.
	Scope string
}

// ConsentFunc is the application hook invoked by [Server.AuthorizeHandler]
// once the /authorize request is validated. The application authenticates
// the resource owner — within the realm of ar.Issuer —, renders its own
// login / consent UI, and returns the decision.
//
// Return contract:
//   - (consent, nil): the handler proceeds — it mints the authorization
//     code (or implicit token) and redirects to the client's redirect URI.
//   - (nil, nil): the ConsentFunc has already written a response to w
//     (typically the login / consent page on the initial GET); the handler
//     does nothing more.
//   - (nil, err): the handler redirects to the client with a server_error.
type ConsentFunc func(w http.ResponseWriter, r *http.Request, ar *AuthorizeRequest) (*Consent, error)

// AuthorizeConfig configures the /authorize endpoint.
type AuthorizeConfig struct {
	// CodeTTL is the authorization-code lifetime. Defaults to 10 minutes
	// (RFC 6749 §4.1.2) when zero.
	CodeTTL time.Duration
	// AllowImplicit enables the legacy implicit flow (response_type=token).
	//
	// LEGACY — discouraged: the access token is returned in the redirect
	// fragment, exposed to the browser. The OAuth 2.0 Security BCP and
	// OAuth 2.1 drop the implicit flow; [Server.AuthorizeHandler] panics if
	// AllowImplicit is set on a server whose profile is not [Profile20].
	// Opt-in only.
	AllowImplicit bool
	// ImplicitTokens mints the opaque access tokens returned by the
	// implicit flow. Required when AllowImplicit is set.
	ImplicitTokens OpaqueTokenGenerator
	// ImplicitTTL is the implicit access-token lifetime. Defaults to 1h.
	ImplicitTTL time.Duration
}

// AuthorizeHandler returns the http.Handler for the RFC 6749 §3.1
// authorization endpoint. It serves the authorization-code flow and,
// when [AuthorizeConfig.AllowImplicit] is set, the legacy implicit flow.
//
// The handler validates the request (client, redirect URI, response type,
// scope, PKCE), resolves its issuer through the [IssuerResolver] — the
// realm the code, or implicit token, is bound to — and then calls consent.
// The library owns the protocol plumbing — request validation, code /
// token minting, the redirect — while the application owns the login and
// consent UI through the [ConsentFunc].
//
// Errors that occur before the redirect URI is trusted (unknown client,
// unregistered redirect URI) are returned directly with a 400 status and
// are NOT redirected, per RFC 6749 §4.1.2.1 (open-redirector protection).
// So is a response_mode other than the one the handler answers in —
// fragment for an enabled implicit flow, query otherwise (OAuth 2.0
// Multiple Response Type Encoding Practices §2.1; OIDC Core 1.0
// incorporating errata set 2, §3.1.2.6). Every later error is redirected
// back to the client — in the query string for the code flow, in the
// fragment for the implicit flow — and only with an error code the
// authorization endpoint defines.
//
// AuthorizeHandler panics on a nil consent, and on an implicit-flow
// misconfiguration (AllowImplicit on a non-Profile20 server, or without an
// ImplicitTokens generator).
func (s *Server) AuthorizeHandler(cfg AuthorizeConfig, consent ConsentFunc) http.Handler {
	if consent == nil {
		panic("oauth2: AuthorizeHandler: nil ConsentFunc")
	}

	if cfg.AllowImplicit {
		if !s.cfg.Profile.AllowsLegacyGrant() {
			panic("oauth2: AuthorizeHandler: AllowImplicit requires Profile20")
		}

		if cfg.ImplicitTokens == nil {
			panic("oauth2: AuthorizeHandler: AllowImplicit requires an ImplicitTokens generator")
		}
	}

	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = defaultAuthCodeTTL
	}

	if cfg.ImplicitTTL <= 0 {
		cfg.ImplicitTTL = defaultImplicitTTL
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveAuthorize(cfg, consent, w, r)
	})
}

func (s *Server) serveAuthorize(cfg AuthorizeConfig, consent ConsentFunc, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		s.notifyError(r.Context(), ErrInvalidRequest.WithDescription("/authorize requires GET or POST"))
		http.Error(w, "oauth2: /authorize requires GET or POST", http.StatusMethodNotAllowed)

		return
	}

	if err := r.ParseForm(); err != nil {
		s.notifyError(r.Context(), ErrInvalidRequest.WithCause(err))
		http.Error(w, "oauth2: malformed authorization request", http.StatusBadRequest)

		return
	}

	// Client and redirect URI come first: a failure here MUST NOT redirect
	// (the redirect target is not yet trusted). The refusal is deliberately
	// opaque on the wire, so the hook is the only place the cause shows up.
	client, err := s.cfg.ClientStore.LoadClient(r.Context(), r.FormValue("client_id"))
	if err != nil || client == nil {
		s.notifyError(r.Context(), ErrInvalidClient.WithDescription("unknown or invalid client").WithCause(err))
		http.Error(w, "oauth2: unknown or invalid client", http.StatusBadRequest)

		return
	}

	redirectURI, ok := resolveRedirectURI(client, r.FormValue("redirect_uri"))
	if !ok {
		s.notifyError(r.Context(), ErrInvalidRequest.WithDescription("missing or unregistered redirect_uri"))
		http.Error(w, "oauth2: missing or unregistered redirect_uri", http.StatusBadRequest)

		return
	}

	// The response mode decides how every later answer travels: one the
	// handler cannot honor leaves no way to answer the client at all.
	if !responseModeSupported(cfg, r) {
		s.notifyError(r.Context(), ErrInvalidRequest.WithDescription("unsupported response_mode"))
		http.Error(w, "oauth2: unsupported response_mode", http.StatusBadRequest)

		return
	}

	// From here on the redirect URI is trusted: errors travel back to the
	// client as a redirect.
	st, ok := s.validateAuthorize(cfg, w, r, client, redirectURI)
	if !ok {
		return
	}

	s.authorize(cfg, consent, w, r, st)
}

// authorizeState is a validated /authorize request: the snapshot the
// server works from. Callbacks only ever get copies of it, so whatever they
// do to the [AuthorizeRequest] they are handed, the redirect target, the
// state, the scope, the PKCE parameters and the issuer the server uses are
// the ones it validated.
type authorizeState struct {
	ar AuthorizeRequest
	// audience is the audience the IssuerResolver returned with ar.Issuer;
	// the implicit flow stamps it on its access token.
	audience string
	// fragment reports that responses travel in the redirect fragment (the
	// implicit flow, RFC 6749 §4.2.2) rather than in the query string.
	fragment bool
}

// request returns a copy of the validated request for a callback.
func (st *authorizeState) request() *AuthorizeRequest {
	ar := st.ar

	return &ar
}

// validateAuthorize validates the request behind a trusted redirect URI:
// it resolves the issuer, the flow, the scope and the PKCE parameters, and
// answers the first failure with a redirect. The issuer comes first, so
// every later redirect is answered within the realm of the request.
func (s *Server) validateAuthorize(
	cfg AuthorizeConfig,
	w http.ResponseWriter,
	r *http.Request,
	client Client,
	redirectURI string,
) (*authorizeState, bool) {
	state := r.FormValue("state")

	// An unsupported response type is answered in the query string.
	flow, flowErr := resolveFlow(cfg, r.FormValue("response_type"))
	fragment := flowErr == nil && flow == flowImplicit

	issuer, audience, err := s.cfg.IssuerResolver.Resolve(r.Context(), r)
	if err != nil {
		s.redirectAuthorizeError(w, r, redirectURI, state, ErrServerError.WithCause(err), fragment)

		return nil, false
	}

	if flowErr != nil {
		s.redirectAuthorizeError(w, r, redirectURI, state, flowErr, false)

		return nil, false
	}

	ar, oerr := s.parseAuthorizeRequest(r, client, redirectURI, flow)
	if oerr != nil {
		s.redirectAuthorizeError(w, r, redirectURI, state, oerr, fragment)

		return nil, false
	}

	ar.Issuer = issuer

	return &authorizeState{ar: *ar, audience: audience, fragment: fragment}, true
}

// authorize runs the ConsentFunc on a validated request and issues what
// the resource owner granted.
func (s *Server) authorize(cfg AuthorizeConfig, consent ConsentFunc, w http.ResponseWriter, r *http.Request, st *authorizeState) {
	decision, err := consent(w, r, st.request())
	if err != nil {
		s.refuseAuthorize(w, r, st, ErrServerError.WithDescription("consent handler failed").WithCause(err))

		return
	}

	if decision == nil {
		// The ConsentFunc rendered its own response (login / consent page).
		return
	}

	if !decision.Approved {
		s.refuseAuthorize(w, r, st, ErrAccessDenied.WithDescription("the resource owner denied the request"))

		return
	}

	granted, err := grantedScope(&st.ar, decision)
	if err != nil {
		s.refuseAuthorize(w, r, st, ErrInvalidScope.WithDescription("granted scope exceeds the request"))

		return
	}

	grant := authorizedGrant{subject: decision.Subject, scope: granted, now: s.cfg.Now()}

	if st.fragment {
		s.issueImplicitToken(cfg, w, r, st, grant)

		return
	}

	s.issueAuthorizationCode(cfg, w, r, st, grant)
}

// authorizedGrant is what an approved authorization issues: to whom, which
// scope, and when.
type authorizedGrant struct {
	subject string
	scope   string
	now     time.Time
}

// refuseAuthorize redirects oerr back to the client of the validated
// request st, in the flow's response mode.
func (s *Server) refuseAuthorize(w http.ResponseWriter, r *http.Request, st *authorizeState, oerr *Error) {
	s.redirectAuthorizeError(w, r, st.ar.RedirectURI, st.ar.State, oerr, st.fragment)
}

// responseModeSupported reports whether the request's response_mode is
// the mode the handler answers in (OAuth 2.0 Multiple Response Type
// Encoding Practices §2.1): fragment for the implicit flow when it is
// enabled (RFC 6749 §4.2.2), query for every other request, errors
// included. An absent or empty one (RFC 6749 §3.1) is that default. Any
// other value — the other mode, form_post, an unknown one — cannot be
// honored, and the answer could not even be encoded as the client
// expects: OIDC Core 1.0 incorporating errata set 2, §3.1.2.6, answers it
// with a bare 400 Bad Request.
func responseModeSupported(cfg AuthorizeConfig, r *http.Request) bool {
	mode := r.FormValue("response_mode")
	if mode == "" {
		return true
	}

	if cfg.AllowImplicit && r.FormValue("response_type") == responseTypeToken {
		return mode == responseModeFragment
	}

	return mode == responseModeQuery
}

// resolveFlow maps the response_type parameter to a flow, refusing the
// implicit flow when it is not enabled. The description never echoes the
// request.
func resolveFlow(cfg AuthorizeConfig, responseType string) (authorizeFlow, *Error) {
	switch responseType {
	case responseTypeCode:
		return flowCode, nil
	case responseTypeToken:
		if !cfg.AllowImplicit {
			return 0, ErrUnsupportedResponseType.WithDescription("the implicit flow is not enabled")
		}

		return flowImplicit, nil
	default:
		return 0, ErrUnsupportedResponseType.WithDescription("response_type is not supported")
	}
}

// parseAuthorizeRequest validates the scope and (for the code flow) the
// PKCE parameters, returning the [AuthorizeRequest] or an [*Error].
func (s *Server) parseAuthorizeRequest(r *http.Request, client Client, redirectURI string, flow authorizeFlow) (*AuthorizeRequest, *Error) {
	scope, err := authorizeScope(r.FormValue("scope"), client.Scopes())
	if err != nil {
		return nil, ErrInvalidScope.WithDescription(err.Error())
	}

	challenge := r.FormValue("code_challenge")
	method := r.FormValue("code_challenge_method")

	// PKCE applies to the authorization-code flow only.
	if flow == flowCode {
		if perr := s.validateAuthorizePKCE(challenge, method); perr != nil {
			return nil, ErrInvalidRequest.WithDescription(perr.Error())
		}
	}

	return &AuthorizeRequest{
		Client:              client,
		ResponseType:        r.FormValue("response_type"),
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               r.FormValue("state"),
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		Nonce:               r.FormValue("nonce"),
	}, nil
}

// validateAuthorizePKCE enforces the profile's PKCE policy and the RFC 7636
// §4.2 challenge syntax on the /authorize parameters. Presence, method and
// profile are checked first, so they keep their errors when a request
// breaks several rules. The descriptions never echo the input.
func (s *Server) validateAuthorizePKCE(challenge, method string) error {
	if challenge == "" {
		if s.cfg.Profile.RequiresPKCE() {
			return errors.New("code_challenge is required")
		}

		return nil
	}

	// RFC 7636 §4.3: an absent code_challenge_method means "plain".
	m := pkce.Method(method)
	if m == "" {
		m = pkce.MethodPlain
	}

	switch m {
	case pkce.MethodPlain:
		if !s.cfg.Profile.AllowsPKCEPlain() {
			return errors.New("code_challenge_method plain is refused by the active profile")
		}
	case pkce.MethodS256:
		// S256 is always acceptable.
	default:
		return errors.New("unsupported code_challenge_method")
	}

	if !pkce.ValidChallenge(m, challenge) {
		return fmt.Errorf("malformed %s code_challenge", m)
	}

	return nil
}

// issueAuthorizationCode mints the code, persists it, and redirects.
func (s *Server) issueAuthorizationCode(
	cfg AuthorizeConfig,
	w http.ResponseWriter,
	r *http.Request,
	st *authorizeState,
	grant authorizedGrant,
) {
	raw, err := randomCode()
	if err != nil {
		s.refuseAuthorize(w, r, st, ErrServerError.WithCause(err))

		return
	}

	// Authorization codes are stored pepper-free (HashToken(nil, …)); the
	// authorization_code grant looks them up the same way.
	code := &AuthorizationCode{
		Code:                raw,
		CodeHash:            HashToken(nil, raw),
		ClientID:            st.ar.Client.ID(),
		Subject:             grant.subject,
		RedirectURI:         st.ar.RedirectURI,
		Scope:               grant.scope,
		CodeChallenge:       st.ar.CodeChallenge,
		CodeChallengeMethod: st.ar.CodeChallengeMethod,
		Nonce:               st.ar.Nonce,
		IssuedAt:            grant.now,
		ExpiresAt:           grant.now.Add(cfg.CodeTTL),
		Issuer:              st.ar.Issuer,
	}

	if err := s.cfg.Storage.SaveAuthorizationCode(r.Context(), code); err != nil {
		s.refuseAuthorize(w, r, st, ErrServerError.WithCause(err))

		return
	}

	params := url.Values{"code": {raw}}
	if st.ar.State != "" {
		params.Set("state", st.ar.State)
	}

	//nolint:gosec // G710: redirectURI is exact-matched against the client's registered URIs by resolveRedirectURI
	http.Redirect(w, r, authorizeRedirectTarget(st.ar.RedirectURI, params, false), http.StatusFound)
}

// issueImplicitToken mints an access token, persists it, and redirects it
// back in the URL fragment (RFC 6749 §4.2.2).
func (s *Server) issueImplicitToken(
	cfg AuthorizeConfig,
	w http.ResponseWriter,
	r *http.Request,
	st *authorizeState,
	grant authorizedGrant,
) {
	raw, hash, err := cfg.ImplicitTokens.Generate(r.Context())
	if err != nil {
		s.refuseAuthorize(w, r, st, ErrServerError.WithCause(err))

		return
	}

	at := &AccessToken{
		Token:     raw,
		TokenHash: hash,
		ClientID:  st.ar.Client.ID(),
		Subject:   grant.subject,
		Scope:     grant.scope,
		Audience:  st.audience,
		IssuedAt:  grant.now,
		ExpiresAt: grant.now.Add(cfg.ImplicitTTL),
		Issuer:    st.ar.Issuer,
	}

	// An implicit token belongs to no family: it is never gated by one.
	if err := s.cfg.Storage.SaveTokenPair(r.Context(), &TokenPair{Access: *at}); err != nil {
		s.refuseAuthorize(w, r, st, ErrServerError.WithCause(err))

		return
	}

	params := url.Values{
		"access_token": {raw},
		"token_type":   {TokenTypeBearer},
		"expires_in":   {strconv.Itoa(int(cfg.ImplicitTTL.Seconds()))},
	}
	if grant.scope != "" {
		params.Set("scope", grant.scope)
	}

	if st.ar.State != "" {
		params.Set("state", st.ar.State)
	}

	//nolint:gosec // G710: redirectURI is exact-matched against the client's registered URIs by resolveRedirectURI
	http.Redirect(w, r, authorizeRedirectTarget(st.ar.RedirectURI, params, true), http.StatusFound)
}

// grantedScope resolves the scope to grant: the consent value when it
// narrows the request, the request scope otherwise. Broadening is refused.
func grantedScope(ar *AuthorizeRequest, decision *Consent) (string, error) {
	if decision.Scope == "" {
		return ar.Scope, nil
	}

	return authorizeScope(decision.Scope, strings.Fields(ar.Scope))
}

// resolveRedirectURI returns the redirect URI to use: the requested one
// when it exactly matches a registered URI, or the sole registered URI
// when the request omitted the parameter. RFC 6749 §3.1.2.3 mandates the
// exact match.
func resolveRedirectURI(client Client, requested string) (string, bool) {
	registered := client.RedirectURIs()

	if requested == "" {
		if len(registered) == 1 {
			return registered[0], true
		}

		return "", false
	}

	if slices.Contains(registered, requested) {
		return requested, true
	}

	return "", false
}

// errScopeNotAllowed reports a requested scope outside the allowed set. Its
// text is the error_description: it never echoes the request.
var errScopeNotAllowed = errors.New("a requested scope is not allowed for this client")

// authorizeScope checks that every requested scope is in the allowed set
// and returns the normalized (space-joined) scope. An empty allowed set
// means the client carries no scope restriction.
func authorizeScope(requested string, allowed []string) (string, error) {
	fields := strings.Fields(requested)

	if len(allowed) == 0 {
		return strings.Join(fields, " "), nil
	}

	for _, s := range fields {
		if !slices.Contains(allowed, s) {
			return "", errScopeNotAllowed
		}
	}

	return strings.Join(fields, " "), nil
}

// redirectAuthorizeError sends an RFC 6749 §4.1.2.1 / §4.2.2.1 error
// response by redirecting back to the client's redirect URI. The envelope —
// cause included — is handed to the configured [ErrorHook] first: the
// redirect carries only the code and the description.
func (s *Server) redirectAuthorizeError(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI, state string,
	oerr *Error,
	useFragment bool,
) {
	s.notifyError(r.Context(), oerr)

	params := url.Values{"error": {oerr.Code}}
	if oerr.Description != "" {
		params.Set("error_description", oerr.Description)
	}

	if state != "" {
		params.Set("state", state)
	}

	//nolint:gosec // G710: redirectURI is exact-matched against the client's registered URIs by resolveRedirectURI
	http.Redirect(w, r, authorizeRedirectTarget(redirectURI, params, useFragment), http.StatusFound)
}

// authorizeRedirectTarget builds the redirect URL: params land in the
// fragment for the implicit flow (RFC 6749 §4.2.2) and in the query string
// otherwise. A registered redirect URI never carries a fragment, so the
// implicit case appends one safely.
func authorizeRedirectTarget(redirectURI string, params url.Values, useFragment bool) string {
	if useFragment {
		return redirectURI + "#" + params.Encode()
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}

	q := u.Query()

	for k, vs := range params {
		for _, v := range vs {
			q.Set(k, v)
		}
	}

	u.RawQuery = q.Encode()

	return u.String()
}

// randomCode returns a 256-bit base64url authorization code.
func randomCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth2: read random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
