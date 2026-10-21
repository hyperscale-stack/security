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

	"github.com/hyperscale-stack/security/oauth2/internal/param"
	"github.com/hyperscale-stack/security/oauth2/internal/scopes"
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

// grantType returns the grant type a client declares to use the flow (RFC
// 7591 §2.1): authorization_code for response_type=code, implicit for
// response_type=token.
func (f authorizeFlow) grantType() string {
	if f == flowImplicit {
		return GrantTypeImplicit
	}

	return GrantTypeAuthorizationCode
}

// errResponseTypeNotDeclared answers a response type whose grant the client
// does not declare: unauthorized_client, "not authorized to request an
// authorization code / access token using this method" (RFC 6749 §4.1.2.1,
// §4.2.2.1).
var errResponseTypeNotDeclared = ErrUnauthorizedClient.WithDescription("the client may not use this response type")

// flowRefusal returns nil when c declares the grant of flow, otherwise
// errResponseTypeNotDeclared — with [ErrNoGrantTypesDeclared] as cause when
// c declares no grant type at all.
func flowRefusal(c Client, flow authorizeFlow) *Error {
	switch {
	case ClientAllowsGrantType(c, flow.grantType()):
		return nil
	case len(c.GrantTypes()) == 0:
		return errResponseTypeNotDeclared.WithCause(ErrNoGrantTypesDeclared)
	default:
		return errResponseTypeNotDeclared
	}
}

// OpaqueTokenGenerator mints opaque tokens — a raw value plus the storage
// hash. The token sub-package's OpaqueRefreshAdapter and OpaqueCodeAdapter
// satisfy it; it is the type the implicit flow uses to issue access tokens.
type OpaqueTokenGenerator interface {
	Generate(ctx context.Context) (raw, hash string, err error)
}

// AuthorizeRequest is the parsed and validated /authorize request handed to
// a [ConsentFunc]. By the time the ConsentFunc sees it, the client, the
// redirect URI, the response type, the scope and the PKCE parameters are
// verified and the issuer is resolved. It holds the values the server
// uses — an empty occurrence of a parameter omitted (RFC 6749 §3.1) — the
// ones to show the resource owner. It is a read-only copy of the
// request the handler validated: a callback changing any field but
// ExtensionRequest, or the identity of the Client it shares with the server,
// fails the authorization with server_error ([ErrAuthorizeRequestModified]).
// A consent narrows the grant through [Consent.Scope]. The values Client and
// ExtensionRequest point to are shared: never mutate them.
type AuthorizeRequest struct {
	// Client is the resolved, registered client.
	Client Client
	// ResponseType is the requested response type ("code" or "token").
	ResponseType string
	// RedirectURI is the validated redirect URI: a registered one
	// ([ValidateRedirectURI]) matched exactly, or a registered loopback IP
	// redirect URI with the port the request set (RFC 8252 §7.3).
	RedirectURI string
	// Scope is the requested scope, already checked against the client's
	// allowed scopes, in canonical form: its RFC 6749 §3.3 tokens joined by
	// a single SP, duplicates dropped.
	Scope string
	// State is the opaque client state echoed back on the redirect: at most
	// [MaxStateLength] bytes of VSCHAR (RFC 6749 Appendix A.5).
	State string
	// CodeChallenge / CodeChallengeMethod carry the PKCE parameters
	// (RFC 7636) of a code request. Both are empty when the request carries
	// no code_challenge, and for the implicit flow, which records none. For
	// the code flow they are validated before the ConsentFunc runs: the
	// method is allowed by the profile and the challenge is well-formed for
	// it (RFC 7636 §4.2).
	CodeChallenge       string
	CodeChallengeMethod string
	// Nonce echoes the OIDC nonce parameter, when present: at most
	// [MaxNonceLength] bytes of valid UTF-8 without NUL.
	Nonce string
	// Issuer is the issuer the IssuerResolver returned for the request: the
	// realm the authorization code — or implicit access token — is bound
	// to. A ConsentFunc authenticates the resource owner within it: a
	// session established at another issuer is no authentication here.
	Issuer string
	// ExtensionRequest is what the server's [Extension] returned from
	// ValidateAuthorizeRequest — its validated view of its own parameters,
	// e.g. an OpenID Connect provider's prompt and max_age; nil without an
	// extension, or when it has nothing to add. The value is shared: never
	// mutate it.
	ExtensionRequest any
}

// Consent is the resource-owner decision returned by a [ConsentFunc].
type Consent struct {
	// Approved reports whether the resource owner granted the request.
	Approved bool
	// Subject is the authenticated resource-owner identifier. An approval
	// MUST name one, of at most 255 bytes (OpenID Connect Core §2): an
	// empty or longer one fails the request with server_error, nothing
	// issued.
	Subject string
	// Scope is the granted scope. Empty — or SPs only — means "exactly what
	// was requested"; otherwise its RFC 6749 §3.3 tokens (SP-separated, at
	// most 100 and 4096 bytes) MUST be a subset of [AuthorizeRequest.Scope]:
	// the consent step may narrow the grant but never broaden it — nothing
	// can be added to a request without scope. Anything else fails the
	// request with invalid_scope, nothing issued.
	Scope string
	// Refusal, on a decision that does not approve the request, is the
	// error redirected to the client instead of access_denied — e.g.
	// [ErrLoginRequired] or [ErrConsentRequired] for an OpenID Connect
	// prompt=none request the application cannot complete silently (OIDC
	// Core §3.1.2.6). Only the authorization-endpoint codes of RFC 6749
	// §4.1.2.1 and OIDC Core §3.1.2.6 travel; any other is answered
	// server_error. Its Description and URI travel only when they fit the
	// RFC 6749 §4.1.2.1 charset — otherwise they are left out, the code
	// kept — and they reach the client's URL, history and logs: never put
	// personal data in them. An approval carrying a Refusal contradicts
	// itself and fails closed with server_error.
	Refusal *Error
	// ExtensionResult is the trusted, extension-defined result of the
	// authentication and consent — for an OpenID Connect provider, the
	// time, ACR and AMR of the authentication event and the claims released
	// — handed to Extension.CompleteAuthorization on an approval, which
	// validates it and decides what the grant records. It is ignored
	// without an extension and never persisted as is. The value is shared:
	// never mutate it after returning it.
	ExtensionResult any
}

// ConsentFunc is the application hook invoked by [Server.AuthorizeHandler]
// once the /authorize request is validated. The application authenticates
// the resource owner — within the realm of ar.Issuer —, renders its own
// login / consent UI, and returns the decision.
//
// Return contract:
//   - (consent, nil): the handler proceeds. An approval mints the
//     authorization code (or implicit token) and redirects to the client's
//     redirect URI; a refusal redirects its Refusal, or access_denied.
//   - (nil, nil): the ConsentFunc has already written a response to w
//     (typically the login / consent page on the initial GET); the handler
//     does nothing more.
//   - (nil, err): the ConsentFunc failed: the handler redirects to the
//     client with a server_error, whatever err — an [*Error] included,
//     since a refusal is a decision, returned as [Consent.Refusal] — and
//     hands err to the [ErrorHook].
//
// A decision states that the resource owner authenticated: return one only
// then. Before that — a login page left, cancelled or failed — render the
// login page again (nil, nil) or refuse with an interaction code
// ([ErrLoginRequired], [ErrInteractionRequired],
// [ErrAccountSelectionRequired], [ErrConsentRequired]). Any other decision,
// a denial included, is redirected even to a client
// [AuthorizeConfig.TrustedRedirect] does not trust (RFC 9700 §4.11.2).
//
// ar is read-only: a decision returned after changing it is answered with
// a server_error ([ErrAuthorizeRequestModified]); narrow the grant with
// Consent.Scope instead. Render the request from ar, never from r.FormValue:
// r is the request as received, and an empty occurrence of a parameter —
// omitted per RFC 6749 §3.1 — can precede the value the server used.
//
// The authorization endpoint MUST be protected against CSRF (RFC 6749
// §10.12): protect the request carrying the resource owner's decision —
// bind it to their session with a CSRF token (session.CSRFToken /
// VerifyCSRF), or refuse cross-origin browser requests
// (net/http.CrossOriginProtection.Check, as examples/oauth2 does) — not the
// endpoint, to which a client may POST an authorization request from its
// own site (RFC 6749 §3.1). The handler has set X-Frame-Options: DENY,
// Content-Security-Policy: frame-ancestors 'none', Cache-Control: no-store
// and Referrer-Policy: same-origin on w before calling the ConsentFunc: the
// pages it renders cannot be framed (RFC 6749 §10.13, RFC 9700 §4.16).
// Replace them on w.Header() only to let origins you trust frame the page.
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
	// Opt-in only. Once a handler enabling it is built, the metadata
	// document advertises the flow ([Server.MetadataHandler]).
	AllowImplicit bool
	// ImplicitTokens mints the opaque access tokens returned by the
	// implicit flow. Required when AllowImplicit is set.
	ImplicitTokens OpaqueTokenGenerator
	// ImplicitTTL is the implicit access-token lifetime. Defaults to 1h.
	ImplicitTTL time.Duration
	// TrustedRedirect, when set, reports whether the handler may redirect
	// an error to client's validated redirectURI before the resource owner
	// has authenticated: RFC 9700 §4.11.2 — "The authorization server MUST
	// always authenticate the user first … SHOULD only automatically
	// redirect the user agent if it trusts the redirection URI" — lest it
	// serve as a redirector to a phishing page a registered client controls.
	// It is asked at most once per request, and only when the request
	// fails before the resource owner authenticated: a repeated
	// parameter, the state, the response type, the
	// client's grant types, the scope, PKCE, the nonce, the Extension's
	// checks, a ConsentFunc error — and a Consent.Refusal stating that the
	// request cannot complete without showing a user interface
	// (login_required, interaction_required, account_selection_required,
	// consent_required: OpenID Connect Core §3.1.2.6, what a prompt=none
	// request is refused with). For a client it reports untrusted, such an
	// error is answered with a bare error page, never redirected: status
	// 400, or what the error code maps to ([Error.HTTPStatus]: 500
	// server_error, 403 access_denied, 503 temporarily_unavailable). Once
	// the ConsentFunc returned any other decision, the resource owner has
	// authenticated: the code, access_denied, other refusals and later
	// failures are redirected for every client. Nil trusts every
	// registered client: errors are redirected as soon as the redirect URI
	// is validated (RFC 6749 §4.1.2.1). ctx is the request's. It runs on the
	// request goroutine, MUST be fast and safe for concurrent use, and MUST
	// NOT panic.
	TrustedRedirect func(ctx context.Context, client Client, redirectURI string) bool
}

// AuthorizeHandler returns the http.Handler for the RFC 6749 §3.1
// authorization endpoint. It serves the authorization-code flow and,
// when [AuthorizeConfig.AllowImplicit] is set, the legacy implicit flow.
//
// The handler resolves the issuer of the request through the
// [IssuerResolver] — the realm the code, or implicit token, is bound to —
// validates the request (client — known at that issuer, see
// [IssuerBoundClient] —, redirect URI, response type and the client's
// declaration of its grant — authorization_code for code, implicit for
// token, unauthorized_client otherwise —, scope, PKCE), and then calls
// consent.
// The library owns the protocol plumbing — request validation, code /
// token minting, the redirect — while the application owns the login and
// consent UI through the [ConsentFunc].
//
// The parameters the handler reads are single-valued (RFC 6749 §3.1): an
// empty occurrence is omitted, and one included more than once with a value
// is refused — client_id, redirect_uri and response_mode with a bare 400
// that is never redirected (the client, the target or the encoding of the
// answer are ambiguous), whatever else the request repeats; any other with
// a redirected invalid_request, answered in the query when response_type is
// the one repeated (the flow is ambiguous). A repeated state is not echoed.
// Other parameters are left to the extension and the ConsentFunc.
//
// Requests are bounded: their query and body by
// [ServerConfig.MaxRequestBytes] (a bare 400 beyond), the client_id by
// [MaxClientIDLength] (an unknown client beyond), the state by
// [MaxStateLength] and VSCHAR (RFC 6749 Appendix A.5) and the nonce by
// [MaxNonceLength], valid UTF-8 without NUL — both refused with a redirected
// invalid_request, the state not echoed. The PKCE parameters of an implicit
// request are ignored.
//
// The scope is parsed strictly (RFC 6749 §3.3): tokens of printable ASCII
// but the double quote and the backslash, separated by SP — runs of SP are
// tolerated, any other whitespace is not — at most 100 tokens, repetitions
// included, and 4096 bytes; anything else is answered invalid_scope before
// the value is compared with anything. The scope the request carries on is
// canonical: single-SP joined, duplicates dropped.
//
// The redirect URI is a registered one, exactly matched (RFC 6749
// §3.1.2.3) but for the port of a loopback IP redirect URI (RFC 8252 §7.3),
// and valid for [ValidateRedirectURI] under the server's profile — under
// [Profile20BCP] and [Profile21Draft], no http but a loopback IP literal
// (RFC 9700 §2.6). Responses keep its query as
// registered, byte for byte (RFC 6749 §3.1.2).
//
// The issuer comes first: when the [IssuerResolver] fails, or returns an
// issuer the server cannot use ([ErrInvalidIssuer]), the request is
// answered with a bare 500, never redirected and before any client is
// loaded — no answer could name the issuer (RFC 9207 §2), nor the client be
// checked against it ([IssuerBoundClient]).
//
// Errors that occur before the redirect URI is trusted (a client unknown
// at the issuer, an unregistered or invalid redirect URI) are returned
// directly with a 400 status and are NOT redirected, per RFC 6749 §4.1.2.1
// (open-redirector protection).
// So is a response_mode other than the one the handler answers in —
// fragment for an enabled implicit flow, query otherwise (OAuth 2.0
// Multiple Response Type Encoding Practices §2.1; OIDC Core 1.0
// incorporating errata set 2, §3.1.2.6). Every later error is redirected
// back to the client — in the query string for the code flow, in the
// fragment for the implicit flow — and only with an error code the
// authorization endpoint defines; before the resource owner authenticated,
// only to a client [AuthorizeConfig.TrustedRedirect] trusts (RFC 9700
// §4.11.2).
//
// Every response carries X-Frame-Options: DENY, Content-Security-Policy:
// frame-ancestors 'none' (added to any policy already set), Cache-Control:
// no-store and Referrer-Policy: same-origin (RFC 6749 §10.13, RFC 9700
// §4.16, §4.2.4): the pages the ConsentFunc renders cannot be framed nor
// cached, and no Referer carries the request to another origin. A
// redirect answering a POST is a 303 See Other (RFC 9700 §4.12), one
// answering a GET a 302 Found; a method other than GET and POST gets a 405
// listing them in Allow.
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

		s.implicit.Store(true)
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
	setAuthorizeHeaders(w.Header())

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		s.notifyError(r.Context(), ErrInvalidRequest.WithDescription("/authorize requires GET or POST"))
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "oauth2: /authorize requires GET or POST", http.StatusMethodNotAllowed)

		return
	}

	if err := s.parseRequestForm(w, r); err != nil {
		s.refuseUnparsable(w, r, err)

		return
	}

	// The core reads its parameters single-valued, an empty occurrence
	// omitted (RFC 6749 §3.1). A repeated client_id, redirect_uri or
	// response_mode leaves the client, the target or the encoding of any
	// answer ambiguous: refused here, never redirected.
	params, repeated := param.SingleValued(r.Form, authorizeParameters)
	if slices.Contains(unredirectableParameters, repeated) {
		s.notifyError(r.Context(), repeatedParameter(repeated))
		http.Error(w, "oauth2: repeated request parameter", http.StatusBadRequest)

		return
	}

	// The issuer comes before the client: a client bound to other issuers
	// (IssuerBoundClient) is unknown at this one. Without an issuer — the
	// resolver failed, or returned one the server cannot use — no answer
	// could name it (RFC 9207 §2) nor the client be checked against it: an
	// outage, answered with a bare 500 that is never redirected.
	issuer, audience, err := s.resolveIssuer(r.Context(), r)
	if err != nil {
		s.notifyError(r.Context(), err)
		http.Error(w, "oauth2: server error", http.StatusInternalServerError)

		return
	}

	// Client and redirect URI come next: a failure here MUST NOT redirect
	// (the redirect target is not yet trusted). The refusal is deliberately
	// opaque on the wire, so the hook is the only place the cause shows up.
	clients := &issuerClients{store: s.cfg.ClientStore, issuer: issuer}

	client, err := clients.LoadClient(r.Context(), params.Get(paramClientID))
	if err != nil && IsCode(err) != CodeInvalidClient {
		// The store failed: an outage, not an unknown client.
		s.notifyError(r.Context(), ErrServerError.WithDescription("client lookup failed").WithCause(err))
		http.Error(w, "oauth2: server error", http.StatusInternalServerError)

		return
	}

	if err != nil || client == nil {
		s.notifyError(r.Context(), clients.explain(ErrInvalidClient.WithDescription("unknown or invalid client").WithCause(err)))
		http.Error(w, "oauth2: unknown or invalid client", http.StatusBadRequest)

		return
	}

	redirectURI, err := resolveRedirectURI(s.cfg.Profile, client, params.Get(paramRedirectURI))
	if err != nil {
		s.refuseRedirectURI(w, r, err)

		return
	}

	// The response mode decides how every later answer travels: one the
	// handler cannot honor leaves no way to answer the client at all.
	if !responseModeSupported(cfg, params) {
		s.notifyError(r.Context(), ErrInvalidRequest.WithDescription("unsupported response_mode"))
		http.Error(w, "oauth2: unsupported response_mode", http.StatusBadRequest)

		return
	}

	// From here on the redirect URI is trusted: errors travel back to the
	// client as a redirect.
	in := authorizeInput{
		client: client, redirectURI: redirectURI, params: params, repeated: repeated, issuer: issuer, audience: audience,
	}

	st, ok := s.validateAuthorize(cfg, w, r, in)
	if !ok {
		return
	}

	s.authorize(cfg, consent, w, r, st)
}

// refuseRedirectURI answers, with a bare 400 that is never redirected (RFC
// 6749 §3.1.2.4), a request whose redirect URI is missing, unregistered, or
// registered but refused by [ValidateRedirectURI]; the cause reaches the
// [ErrorHook] only.
func (s *Server) refuseRedirectURI(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrInvalidRedirectURI) {
		s.notifyError(r.Context(), ErrInvalidRequest.WithDescription("invalid registered redirect_uri").WithCause(err))
		http.Error(w, "oauth2: invalid redirect_uri", http.StatusBadRequest)

		return
	}

	s.notifyError(r.Context(), ErrInvalidRequest.WithDescription("missing or unregistered redirect_uri").WithCause(err))
	http.Error(w, "oauth2: missing or unregistered redirect_uri", http.StatusBadRequest)
}

// refuseUnparsable answers an authorization request parseRequestForm
// refused, with a bare 400: nothing of it can be trusted, its redirect URI
// included.
func (s *Server) refuseUnparsable(w http.ResponseWriter, r *http.Request, err error) {
	oe := formRefusal(err)
	s.notifyError(r.Context(), oe)

	if errors.Is(err, errRequestTooLarge) {
		http.Error(w, "oauth2: authorization request too large", http.StatusBadRequest)

		return
	}

	http.Error(w, "oauth2: malformed authorization request", http.StatusBadRequest)
}

// authorizeState is a validated /authorize request: the snapshot the
// server works from. Callbacks only ever get copies of it, so whatever they
// do to the [AuthorizeRequest] they are handed, the redirect target, the
// state, the scope, the PKCE parameters and the issuer the server uses are
// the ones it validated.
type authorizeState struct {
	ar AuthorizeRequest
	// clientID is the identifier of the validated client, read once: the
	// code and the implicit token are bound to it, and a callback changing
	// the identity of the client it shares with the server is detected.
	clientID string
	// audience is the audience the IssuerResolver returned with ar.Issuer;
	// the implicit flow stamps it on its access token.
	audience string
	// fragment reports that responses travel in the redirect fragment (the
	// implicit flow, RFC 6749 §4.2.2) rather than in the query string.
	fragment bool
	// redirectURIOmitted reports that the request named no redirect_uri:
	// its code may be redeemed without one (RFC 6749 §4.1.3).
	redirectURIOmitted bool
	// trust decides whether errors travel to the client before the
	// resource owner authenticated.
	trust *redirectTrust
	// authenticated reports that the ConsentFunc returned a decision other
	// than an interaction refusal: every later answer is redirected.
	authenticated bool
}

// authorizeTarget is where and how an authorization response travels: the
// trusted redirect URI, the state to echo, the issuer to name, and the
// encoding — the fragment for the implicit flow, the query otherwise.
type authorizeTarget struct {
	redirectURI string
	state       string
	// issuer is the validated issuer identifier the request resolved to.
	issuer   string
	fragment bool
	// trust decides whether an error before authentication travels to the
	// client ([AuthorizeConfig.TrustedRedirect]).
	trust *redirectTrust
}

// redirectTrust is what [AuthorizeConfig.TrustedRedirect] decides from: the
// hook, the client and the redirect URI of one request. A request answers
// once, so the hook is asked at most once.
type redirectTrust struct {
	hook        func(context.Context, Client, string) bool
	client      Client
	redirectURI string
}

// allows reports whether errors before authentication may be redirected:
// always without a hook, otherwise what the hook answers.
func (t *redirectTrust) allows(ctx context.Context) bool {
	return t == nil || t.hook == nil || t.hook(ctx, t.client, t.redirectURI)
}

// responseParams returns the parameters every authorization response to t
// carries: state, echoed when the request carried one (RFC 6749 §4.1.2,
// §4.1.2.1), and iss, the issuer identifier (RFC 9207 §2: a server
// supporting it names itself in every authorization response, error
// responses included) — always known and valid here: a request whose issuer
// is not is answered before any redirect.
func (t authorizeTarget) responseParams() url.Values {
	params := url.Values{paramIss: {t.issuer}}
	if t.state != "" {
		params.Set(paramState, t.state)
	}

	return params
}

// redirect sends the authorization response params to t: 303 for a POST,
// 302 for a GET (redirectStatus).
func (t authorizeTarget) redirect(w http.ResponseWriter, r *http.Request, params url.Values) {
	//nolint:gosec // G710: redirectURI is exact-matched against the client's registered URIs by resolveRedirectURI
	http.Redirect(w, r, authorizeRedirectTarget(t.redirectURI, params, t.fragment), redirectStatus(r))
}

// target returns the authorization-response target of the validated
// request.
func (st *authorizeState) target() authorizeTarget {
	return authorizeTarget{
		redirectURI: st.ar.RedirectURI, state: st.ar.State, issuer: st.ar.Issuer, fragment: st.fragment, trust: st.trust,
	}
}

// request returns a copy of the validated request for a callback.
func (st *authorizeState) request() *AuthorizeRequest {
	ar := st.ar

	return &ar
}

// modified reports whether a callback changed the copy cp it was handed —
// any field but ExtensionRequest, the extension's own — or the identity of
// the client the copy shares with the validated request.
func (st *authorizeState) modified(cp *AuthorizeRequest) bool {
	if cp.Client == nil || cp.Client.ID() != st.clientID || st.ar.Client.ID() != st.clientID {
		return true
	}

	return cp.ResponseType != st.ar.ResponseType ||
		cp.RedirectURI != st.ar.RedirectURI ||
		cp.Scope != st.ar.Scope ||
		cp.State != st.ar.State ||
		cp.CodeChallenge != st.ar.CodeChallenge ||
		cp.CodeChallengeMethod != st.ar.CodeChallengeMethod ||
		cp.Nonce != st.ar.Nonce ||
		cp.Issuer != st.ar.Issuer
}

// refuseModified answers a request a callback modified: server_error, the
// callback's own error, if any, joined to the cause.
func (s *Server) refuseModified(w http.ResponseWriter, r *http.Request, st *authorizeState, err error) {
	s.refuseAuthorize(w, r, st, ErrServerError.WithCause(errors.Join(ErrAuthorizeRequestModified, err)))
}

// authorizeInput is an /authorize request behind a trusted redirect URI:
// its client, the redirect URI resolved for it, its parameters as the core
// reads them — single-valued, an empty occurrence omitted — with the first
// one it includes more than once (RFC 6749 §3.1), and the validated issuer
// it resolved to, with the audience the resolver gave.
type authorizeInput struct {
	client           Client
	redirectURI      string
	params           url.Values
	repeated         string
	issuer, audience string
}

// validateAuthorize validates the request behind a trusted redirect URI —
// a repeated parameter, the flow, the scope and the PKCE parameters — and
// answers the first failure with a redirect, within the realm of the
// request: every answer names its issuer.
func (s *Server) validateAuthorize(
	cfg AuthorizeConfig,
	w http.ResponseWriter,
	r *http.Request,
	in authorizeInput,
) (*authorizeState, bool) {
	// An unsupported — or repeated — response type is answered in the query
	// string, and a repeated or invalid state is not echoed.
	flow, flowErr := resolveFlow(cfg, in.params.Get("response_type"))
	state := in.params.Get(paramState)
	stateValid := validState(state)
	target := authorizeTarget{
		redirectURI: in.redirectURI,
		issuer:      in.issuer,
		fragment:    flowErr == nil && flow == flowImplicit,
		trust:       &redirectTrust{hook: cfg.TrustedRedirect, client: in.client, redirectURI: in.redirectURI},
	}

	if stateValid {
		target.state = state
	}

	// RFC 6749 §4.1.2.1: invalid_request "includes a parameter more than
	// once".
	if in.repeated != "" {
		s.refuseUnauthenticated(w, r, target, repeatedParameter(in.repeated))

		return nil, false
	}

	if !stateValid {
		s.refuseUnauthenticated(w, r, target, errMalformedState)

		return nil, false
	}

	if flowErr != nil {
		s.refuseUnauthenticated(w, r, target, flowErr)

		return nil, false
	}

	if oerr := flowRefusal(in.client, flow); oerr != nil {
		s.refuseUnauthenticated(w, r, target, oerr)

		return nil, false
	}

	ar, oerr := s.parseAuthorizeRequest(in, flow)
	if oerr != nil {
		s.refuseUnauthenticated(w, r, target, oerr)

		return nil, false
	}

	ar.Issuer = in.issuer
	st := &authorizeState{
		ar: *ar, clientID: in.client.ID(), audience: in.audience, fragment: target.fragment,
		redirectURIOmitted: in.params.Get(paramRedirectURI) == "", trust: target.trust,
	}

	if s.cfg.Extension == nil {
		return st, true
	}

	cp := st.request()

	view, err := s.cfg.Extension.ValidateAuthorizeRequest(r.Context(), r, cp)
	if st.modified(cp) {
		s.refuseModified(w, r, st, err)

		return nil, false
	}

	if err != nil {
		s.extensionFailed(w, r, st, err)

		return nil, false
	}

	st.ar.ExtensionRequest = view

	return st, true
}

// extensionFailed answers the error an [Extension] authorization hook
// returned: [ErrUnredirectableRequest] with a bare 400, a protocol [*Error]
// with a redirect — authorization-endpoint codes only, see
// redirectAuthorizeError — and anything else with a redirected
// server_error.
func (s *Server) extensionFailed(w http.ResponseWriter, r *http.Request, st *authorizeState, err error) {
	if errors.Is(err, ErrUnredirectableRequest) {
		s.notifyError(r.Context(), ErrInvalidRequest.WithDescription("authorization request refused without redirect").WithCause(err))
		http.Error(w, "oauth2: invalid authorization request", http.StatusBadRequest)

		return
	}

	var oe *Error
	if !errors.As(err, &oe) || oe == nil {
		oe = ErrServerError.WithDescription("authorization extension failed").WithCause(err)
	}

	s.refuseAuthorize(w, r, st, oe)
}

// authorize runs the ConsentFunc on a validated request and issues what
// the resource owner granted.
func (s *Server) authorize(cfg AuthorizeConfig, consent ConsentFunc, w http.ResponseWriter, r *http.Request, st *authorizeState) {
	cp := st.request()

	decision, err := consent(w, r, cp)
	if err != nil {
		s.refuseAuthorize(w, r, st, ErrServerError.WithDescription("consent handler failed").WithCause(err))

		return
	}

	if decision == nil {
		// The ConsentFunc rendered its own response (login / consent page).
		return
	}

	// A decision means the resource owner authenticated — unless it says
	// the request cannot complete without a user interface.
	st.authenticated = !interactionRefused(decision)

	if st.modified(cp) {
		s.refuseModified(w, r, st, nil)

		return
	}

	if oerr := checkDecision(decision); oerr != nil {
		s.refuseAuthorize(w, r, st, oerr)

		return
	}

	granted, err := grantedScope(&st.ar, decision)
	if err != nil {
		s.refuseAuthorize(w, r, st, ErrInvalidScope.WithDescription("granted scope exceeds the request").WithCause(err))

		return
	}

	grant := authorizedGrant{subject: decision.Subject, scope: granted, now: s.cfg.Now()}

	if s.cfg.Extension != nil && !s.completeAuthorization(w, r, st, decision, &grant) {
		return
	}

	if st.fragment {
		s.issueImplicitToken(cfg, w, r, st, grant)

		return
	}

	s.issueAuthorizationCode(cfg, w, r, st, grant)
}

// maxSubjectLength is the longest Consent.Subject, in bytes, an approval
// may name: OpenID Connect Core 1.0 §2 caps sub at 255 ASCII characters,
// and the SQL store keeps subjects in a VARCHAR(255) column.
const maxSubjectLength = 255

// Why a decision is refused although the ConsentFunc did not fail. They are
// the causes the ErrorHook gets; the client gets a bare server_error.
var (
	errContradictoryDecision = errors.New("oauth2: consent approved the request and refused it")
	errMissingSubject        = errors.New("oauth2: consent approved the request without a subject")
	errLongSubject           = errors.New("oauth2: consent approved a subject longer than 255 bytes")
)

// checkDecision returns the answer to a decision that does not approve the
// request — its Refusal, or access_denied — or that cannot be honored: an
// approval carrying a Refusal, or naming no or an over-long subject, fails
// closed with server_error. It returns nil for a valid approval.
func checkDecision(d *Consent) *Error {
	switch {
	case d.Approved && d.Refusal != nil:
		return ErrServerError.WithCause(errContradictoryDecision).WithCause(d.Refusal)
	case d.Refusal != nil:
		return d.Refusal
	case !d.Approved:
		return ErrAccessDenied.WithDescription("the resource owner denied the request")
	case d.Subject == "":
		return ErrServerError.WithCause(errMissingSubject)
	case len(d.Subject) > maxSubjectLength:
		return ErrServerError.WithCause(errLongSubject)
	default:
		return nil
	}
}

// authorizedGrant is what an approved authorization issues: to whom, which
// scope, when, and the grant context the extension recorded.
type authorizedGrant struct {
	subject string
	scope   string
	now     time.Time
	data    string
}

// completeAuthorization runs Extension.CompleteAuthorization on an
// approved decision and applies the ExtensionGrant it returns to grant. It
// answers a failure itself and reports whether the authorization goes on.
func (s *Server) completeAuthorization(
	w http.ResponseWriter,
	r *http.Request,
	st *authorizeState,
	decision *Consent,
	grant *authorizedGrant,
) bool {
	consent := *decision
	consent.Scope = grant.scope
	cp := st.request()

	g, err := s.cfg.Extension.CompleteAuthorization(r.Context(), cp, consent, grant.now)
	if st.modified(cp) {
		s.refuseModified(w, r, st, err)

		return false
	}

	if err != nil {
		s.extensionFailed(w, r, st, err)

		return false
	}

	scope, oerr := applyExtensionGrant(grant.scope, g)
	if oerr != nil {
		s.refuseAuthorize(w, r, st, oerr)

		return false
	}

	grant.scope, grant.data = scope, g.Data

	return true
}

// refuseAuthorize answers oerr to the client of the validated request st:
// redirected, in the flow's response mode — before the resource owner
// authenticated, only to a client [AuthorizeConfig.TrustedRedirect]
// trusts.
func (s *Server) refuseAuthorize(w http.ResponseWriter, r *http.Request, st *authorizeState, oerr *Error) {
	if st.authenticated {
		s.redirectAuthorizeError(w, r, st.target(), oerr)

		return
	}

	s.refuseUnauthenticated(w, r, st.target(), oerr)
}

// refuseUnauthenticated answers an error detected before the resource owner
// authenticated: redirected when target's client is trusted
// ([AuthorizeConfig.TrustedRedirect]), otherwise a bare page with the status
// of its code (RFC 9700 §4.11.2) — the envelope reported to the
// [ErrorHook] either way.
func (s *Server) refuseUnauthenticated(w http.ResponseWriter, r *http.Request, target authorizeTarget, oerr *Error) {
	if target.trust.allows(r.Context()) {
		s.redirectAuthorizeError(w, r, target, oerr)

		return
	}

	oerr = authorizeWireError(oerr)
	s.notifyError(r.Context(), oerr)
	http.Error(w, "oauth2: authorization request refused: "+oerr.Code, oerr.HTTPStatus())
}

// interactionCodes are the OpenID Connect Core §3.1.2.6 refusals of a
// request that cannot complete without displaying a user interface — the
// answers to prompt=none: no resource owner authenticated.
var interactionCodes = []string{
	CodeLoginRequired, CodeInteractionRequired, CodeAccountSelectionRequired, CodeConsentRequired,
}

// interactionRefused reports whether d refuses the request with one of the
// interactionCodes.
func interactionRefused(d *Consent) bool {
	return d.Refusal != nil && slices.Contains(interactionCodes, d.Refusal.Code)
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
func responseModeSupported(cfg AuthorizeConfig, params url.Values) bool {
	mode := params.Get(paramResponseMode)
	if mode == "" {
		return true
	}

	if cfg.AllowImplicit && params.Get("response_type") == responseTypeToken {
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

// parseAuthorizeRequest validates the scope, (for the code flow) the PKCE
// parameters and the nonce, returning the [AuthorizeRequest] or an
// [*Error].
func (s *Server) parseAuthorizeRequest(in authorizeInput, flow authorizeFlow) (*AuthorizeRequest, *Error) {
	scope, oerr := authorizeScope(in.params.Get(paramScope), in.client.Scopes())
	if oerr != nil {
		return nil, oerr
	}

	challenge, method, perr := s.authorizePKCE(in, flow)
	if perr != nil {
		return nil, ErrInvalidRequest.WithDescription(perr.Error())
	}

	nonce := in.params.Get("nonce")
	if !validNonce(nonce) {
		return nil, errMalformedNonce
	}

	return &AuthorizeRequest{
		Client:              in.client,
		ResponseType:        in.params.Get("response_type"),
		RedirectURI:         in.redirectURI,
		Scope:               scope,
		State:               in.params.Get(paramState),
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		Nonce:               nonce,
	}, nil
}

// authorizePKCE returns the PKCE parameters the request records, or why
// they are refused. PKCE belongs to the authorization-code flow (RFC
// 7636): an implicit request records none, whatever it carries, and a
// code_challenge_method means nothing without a code_challenge (§4.3), so
// it is not recorded alone.
func (s *Server) authorizePKCE(in authorizeInput, flow authorizeFlow) (string, string, error) {
	if flow != flowCode {
		return "", "", nil
	}

	challenge := in.params.Get("code_challenge")
	method := in.params.Get("code_challenge_method")

	if err := s.validateAuthorizePKCE(in.client, challenge, method); err != nil {
		return "", "", err
	}

	if challenge == "" {
		return "", "", nil
	}

	return challenge, method, nil
}

// validateAuthorizePKCE enforces the PKCE policy and the RFC 7636 §4.2
// challenge syntax on the /authorize parameters of client. A challenge is
// required under the profiles that mandate PKCE, and under every profile
// from a client that is not confidential (RFC 9700 §2.1.1: public clients
// MUST use PKCE; an untyped client is not known to be confidential).
// Presence, method and profile are checked first, so they keep their errors
// when a request breaks several rules. The descriptions never echo the
// input.
func (s *Server) validateAuthorizePKCE(client Client, challenge, method string) error {
	if challenge == "" {
		if s.cfg.Profile.RequiresPKCE() || client.Type() != ClientConfidential {
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
		ClientID:            st.clientID,
		Subject:             grant.subject,
		RedirectURI:         st.ar.RedirectURI,
		RedirectURIOmitted:  st.redirectURIOmitted,
		Scope:               grant.scope,
		CodeChallenge:       st.ar.CodeChallenge,
		CodeChallengeMethod: st.ar.CodeChallengeMethod,
		Nonce:               st.ar.Nonce,
		IssuedAt:            grant.now,
		ExpiresAt:           grant.now.Add(cfg.CodeTTL),
		Issuer:              st.ar.Issuer,
		ExtensionData:       grant.data,
	}

	if err := s.cfg.Storage.SaveAuthorizationCode(r.Context(), code); err != nil {
		s.refuseAuthorize(w, r, st, ErrServerError.WithCause(err))

		return
	}

	target := st.target()
	params := target.responseParams()
	params.Set(paramCode, raw)

	target.redirect(w, r, params)
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
		Token:         raw,
		TokenHash:     hash,
		ClientID:      st.clientID,
		Subject:       grant.subject,
		Scope:         grant.scope,
		Audience:      st.audience,
		IssuedAt:      grant.now,
		ExpiresAt:     grant.now.Add(cfg.ImplicitTTL),
		Issuer:        st.ar.Issuer,
		ExtensionData: grant.data,
	}

	// An implicit token belongs to no family: it is never gated by one.
	if err := s.cfg.Storage.SaveTokenPair(r.Context(), &TokenPair{Access: *at}); err != nil {
		s.refuseAuthorize(w, r, st, ErrServerError.WithCause(err))

		return
	}

	target := st.target()
	params := target.responseParams()
	params.Set("access_token", raw)
	params.Set("token_type", TokenTypeBearer)
	params.Set("expires_in", strconv.Itoa(int(cfg.ImplicitTTL.Seconds())))

	if grant.scope != "" {
		params.Set("scope", grant.scope)
	}

	target.redirect(w, r, params)
}

// grantedScope resolves the scope an approval grants: the request's when
// the consent names none — an empty or all-SP Consent.Scope — otherwise the
// consent's tokens, parsed like a request's (RFC 6749 §3.3) and returned
// canonical, each of which MUST be requested: an empty request admits none.
// The request is a subset of the client's registration already, so a grant
// never exceeds request ∩ registration.
func grantedScope(ar *AuthorizeRequest, decision *Consent) (string, error) {
	tokens, err := scopes.Parse(decision.Scope)
	if err != nil {
		return "", err //nolint:wrapcheck // a scopes sentinel, the cause the ErrorHook gets
	}

	if len(tokens) == 0 {
		return ar.Scope, nil
	}

	if !scopes.NewSet(strings.Fields(ar.Scope)).Admits(tokens) {
		return "", errScopeNotAllowed
	}

	return scopes.Join(tokens), nil
}

// Why a requested scope is refused. Their text is the error_description: it
// never echoes the request.
var (
	errScopeNotAllowed = errors.New("a requested scope is not allowed for this client")
	errScopeMalformed  = errors.New("the requested scope is malformed or too large")
)

// authorizeScope checks a requested scope value against the client's allowed
// scopes and returns it canonical: single-SP joined, duplicates dropped. The
// value is parsed strictly (RFC 6749 §3.3: SP-separated NQCHAR tokens), at
// most 100 tokens and 4096 bytes — anything else is invalid_scope
// ("malformed", §4.1.2.1), with the scopes sentinel as cause. Every token
// must be allowed: an empty allowed set admits none ([ErrNoScopesDeclared]
// as cause), and a request without scope gets the empty scope.
func authorizeScope(requested string, allowed []string) (string, *Error) {
	tokens, err := scopes.Parse(requested)
	if err != nil {
		return "", ErrInvalidScope.WithDescription(errScopeMalformed.Error()).WithCause(err)
	}

	if !scopes.NewSet(allowed).Admits(tokens) {
		refusal := ErrInvalidScope.WithDescription(errScopeNotAllowed.Error())
		if len(allowed) == 0 {
			refusal = refusal.WithCause(ErrNoScopesDeclared)
		}

		return "", refusal
	}

	return scopes.Join(tokens), nil
}

// redirectAuthorizeError sends an RFC 6749 §4.1.2.1 / §4.2.2.1 error
// response by redirecting back to the client's redirect URI. Only a code
// the authorization endpoint defines travels (authorizeErrorCodes), any
// other is answered server_error; a description or error_uri outside the
// RFC 6749 charset is left out. Like every authorization response, it
// echoes the state and names the issuer (RFC 9207 §2). The envelope — cause
// included — is handed to the configured [ErrorHook] first: the redirect
// carries only the code, the description and the URI.
func (s *Server) redirectAuthorizeError(w http.ResponseWriter, r *http.Request, target authorizeTarget, oerr *Error) {
	oerr = authorizeWireError(oerr)
	s.notifyError(r.Context(), oerr)

	params := target.responseParams()
	params.Set("error", oerr.Code)

	if desc := wireDescription(oerr.Description); desc != "" {
		params.Set("error_description", desc)
	}

	if uri := wireURI(oerr.URI); uri != "" {
		params.Set("error_uri", uri)
	}

	target.redirect(w, r, params)
}

// authorizeRedirectTarget builds the redirect URL: params land in the
// fragment for the implicit flow (RFC 6749 §4.2.2) and in the query string
// otherwise, appended to the redirect URI as registered — its query "MUST
// be retained" (RFC 6749 §3.1.2), byte for byte. A validated redirect URI
// has no fragment and no query parameter named like a response one
// ([ValidateRedirectURI]). The separator depends on the query component —
// everything after the first "?" — not on the whole URI: a query whose last
// value ends with "?" still needs one.
func authorizeRedirectTarget(redirectURI string, params url.Values, useFragment bool) string {
	_, query, hasQuery := strings.Cut(redirectURI, "?")

	switch {
	case useFragment:
		return redirectURI + "#" + params.Encode()
	case !hasQuery:
		return redirectURI + "?" + params.Encode()
	case query == "", strings.HasSuffix(query, "&"):
		return redirectURI + params.Encode()
	default:
		return redirectURI + "&" + params.Encode()
	}
}

// randomCode returns a 256-bit base64url authorization code.
func randomCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth2: read random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
