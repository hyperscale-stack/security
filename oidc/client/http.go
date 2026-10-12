// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Binding cookie parameters.
const (
	// cookiePrefix names binding cookies: __Host- makes the browser require
	// Secure, Path=/ and no Domain, so a sibling subdomain cannot plant one
	// (rfc6265bis-22 §4.1.3.2).
	cookiePrefix = "__Host-oidc-"
	// insecureCookiePrefix names them with Config.InsecureCookies.
	insecureCookiePrefix = "oidc-"
	// cookieNameHashLength is the number of hex digits of the state hash
	// that tell the cookies of parallel logins apart.
	cookieNameHashLength = 16
	// maxLoginCookies bounds the binding cookies a browser keeps.
	maxLoginCookies = 4
	// maxCallbackBody bounds a form_post callback body.
	maxCallbackBody = 64 << 10
)

// StartLogin begins a login for net/http: it runs Begin, keeps the binding
// secret in an HttpOnly __Host- cookie named after the state — parallel
// logins in several tabs do not clobber each other — and answers 303 See
// Other to the authorization request, with Cache-Control: no-store.
//
// The cookie is SameSite=Lax for the query response mode — the callback
// is a top-level cross-site GET, which carries Lax cookies (rfc6265bis-22
// §5.6.7.1) — and SameSite=None for form_post, whose callback is a
// cross-site POST that Lax cookies do not reach (§8.8.3). It lives as long
// as the transaction. At most four pending logins keep their cookie: the
// oldest are expired, so a page firing login starts cannot grow the Cookie
// header without bound — still, start logins on a user action (POST with
// CSRF protection, or a same-site check) when several connections exist.
//
// Nothing is written when StartLogin returns an error.
func (c *Client) StartLogin(w http.ResponseWriter, r *http.Request, opts AuthOptions) error {
	ar, err := c.Begin(r.Context(), opts)
	if err != nil {
		return err
	}

	c.expireOldCookies(w, r)
	http.SetCookie(w, c.bindingCookie(c.cookieName(ar.State), ar.Binding, int(c.cfg.TransactionTTL/time.Second)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, ar.URL, http.StatusSeeOther)

	return nil
}

// HandleCallback completes a login for net/http. It reads the response
// as the connection's response mode delivers it — a GET with the response
// in the query, or a POST of an application/x-www-form-urlencoded body of
// at most 64 KiB (or the r.PostForm a middleware already parsed) without
// response parameters in the query — reads and
// expires the binding cookie of the response's state, sets Cache-Control:
// no-store and Referrer-Policy: no-referrer (RFC 9700 §4.2.4), and calls
// Complete with the URL the request was received on: the RedirectURL's
// scheme (TLS is often terminated before the application), the host of
// the Host header (r.Host), r.URL's path and query.
//
// Behind a reverse proxy, preserve the Host header (or restore the public
// host before HandleCallback, from a header only your proxy sets); a proxy
// rewriting hosts or paths needs Complete with the public URL instead.
//
// The application then writes the response: on success, create a fresh
// session and answer 303 to a clean URL, so the code leaves the browser
// history (RFC 9700 §4.3.1). It MUST NOT write headers before. Exempt the
// callback route from a CSRF middleware in form_post mode: the cross-site
// POST is the protocol, and the binding cookie is its CSRF defense.
func (c *Client) HandleCallback(w http.ResponseWriter, r *http.Request) (*Identity, error) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	params, err := c.readCallback(w, r)
	if err != nil {
		return nil, err
	}

	var binding string

	if states := params[paramState]; len(states) == 1 {
		if _, ok := decodeSecret(states[0]); ok {
			name := c.cookieName(states[0])
			if ck, err := r.Cookie(name); err == nil {
				binding = ck.Value
			}

			http.SetCookie(w, c.bindingCookie(name, "", -1))
		}
	}

	// The scheme is the RedirectURL's: TLS is often terminated before the
	// application. The host is the Host header the user agent sent.
	received := &url.URL{
		Scheme: c.redirect.Scheme, Host: r.Host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery,
	}

	return c.Complete(r.Context(), Callback{Mode: c.cfg.ResponseMode, URL: received, Params: params, Binding: binding})
}

// readCallback reads the response parameters as the response mode
// delivers them.
func (c *Client) readCallback(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed query", ErrInvalidCallback)
	}

	if c.cfg.ResponseMode == ResponseModeQuery {
		if r.Method != http.MethodGet {
			return nil, fmt.Errorf("%w: the query response mode answers with a GET", ErrInvalidCallback)
		}

		return query, nil
	}

	switch {
	case r.Method != http.MethodPost:
		return nil, fmt.Errorf("%w: the form_post response mode answers with a POST", ErrInvalidCallback)
	case !hasMediaType(r.Header.Get("Content-Type"), formContentType):
		return nil, fmt.Errorf("%w: form_post body must be form-urlencoded", ErrInvalidCallback)
	case slices.ContainsFunc(responseParams, query.Has):
		return nil, fmt.Errorf("%w: response parameter in the query of a form_post callback", ErrInvalidCallback)
	}

	if r.PostForm != nil { // a middleware already parsed the body (r.ParseForm)
		return r.PostForm, nil
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCallbackBody))
	if err != nil {
		return nil, fmt.Errorf("%w: body: %w", ErrInvalidCallback, err)
	}

	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("%w: malformed body", ErrInvalidCallback)
	}

	return params, nil
}

func (c *Client) cookiePrefix() string {
	if c.cfg.InsecureCookies {
		return insecureCookiePrefix
	}

	return cookiePrefix
}

// cookieName is the binding cookie of the login whose state is state.
func (c *Client) cookieName(state string) string {
	return c.cookiePrefix() + stateHashFor(state)[:cookieNameHashLength]
}

// bindingCookie builds a binding cookie; maxAge < 0 expires it.
func (c *Client) bindingCookie(name, value string, maxAge int) *http.Cookie {
	sameSite := http.SameSiteLaxMode
	if c.cfg.ResponseMode == ResponseModeFormPost {
		sameSite = http.SameSiteNoneMode
	}

	return &http.Cookie{ //nolint:gosec // G124: Secure is false only with Config.InsecureCookies, the explicit local-development opt-in
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   !c.cfg.InsecureCookies,
		HttpOnly: true,
		SameSite: sameSite,
	}
}

// expireOldCookies expires the oldest binding cookies so that, with the one
// being set, at most maxLoginCookies remain. Cookies of equal paths come
// oldest first in the Cookie header (RFC 6265 §5.4).
func (c *Client) expireOldCookies(w http.ResponseWriter, r *http.Request) {
	var names []string

	for _, ck := range r.Cookies() {
		if strings.HasPrefix(ck.Name, c.cookiePrefix()) && !slices.Contains(names, ck.Name) {
			names = append(names, ck.Name)
		}
	}

	for _, name := range names[:max(0, len(names)-maxLoginCookies+1)] {
		http.SetCookie(w, c.bindingCookie(name, "", -1))
	}
}
