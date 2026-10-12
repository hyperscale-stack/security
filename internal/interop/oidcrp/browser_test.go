// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcrp_test

import (
	"context"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/example/server/storage"
)

// laxCookies rewrites the SameSite attribute of the cookies a response
// sets to Lax, as a misconfigured form_post deployment would.
type laxCookies struct{ http.ResponseWriter }

func (w laxCookies) WriteHeader(code int) {
	cookies := w.Header()["Set-Cookie"]
	for i := range cookies {
		cookies[i] = strings.Replace(cookies[i], "SameSite=None", "SameSite=Lax", 1)
	}

	w.ResponseWriter.WriteHeader(code)
}

// browserConnection is one connection of the relying party under test.
type browserConnection struct {
	mode    oidcclient.ResponseMode
	lax     bool  // rewrite the binding cookie to SameSite=Lax
	want    error // nil: the login succeeds
	results chan error
}

// TestBrowserBindingCookie runs logins in a real browser — headless Chrome
// driven by chromedp; opt in with OIDC_BROWSER_TESTS=1 — with the relying
// party on https://localhost and the provider on https://127.0.0.1: two
// sites, so the browser applies SameSite to the binding cookie. A query
// callback is a top-level cross-site GET, which carries the Lax cookie; a
// form_post callback is a cross-site POST, which carries the None cookie
// but not a Lax one. Every completed callback deletes its cookie.
func TestBrowserBindingCookie(t *testing.T) {
	if os.Getenv("OIDC_BROWSER_TESTS") != "1" {
		t.Skip("set OIDC_BROWSER_TESTS=1 to run the browser tests (requires Chrome)")
	}

	rp := httptest.NewUnstartedServer(nil)
	_, port, err := net.SplitHostPort(rp.Listener.Addr().String())
	require.NoError(t, err)

	origin := "https://localhost:" + port
	connections := map[string]*browserConnection{
		"query":    {mode: oidcclient.ResponseModeQuery},
		"formpost": {mode: oidcclient.ResponseModeFormPost},
		"lax":      {mode: oidcclient.ResponseModeFormPost, lax: true, want: oidcclient.ErrBindingMismatch},
	}

	var clients []*storage.Client
	for name := range connections {
		clients = append(clients, storage.WebClient("rp-"+name, clientSecret, origin+"/oidc/"+name+"/callback"))
	}

	p := startProvider(t, clients...)
	mux := http.NewServeMux()

	for name, conn := range connections {
		conn.results = make(chan error, 1)
		c := p.relyingParty(t, name, func(cfg *oidcclient.Config) {
			cfg.ClientID = "rp-" + name
			cfg.RedirectURL = origin + "/oidc/" + name + "/callback"
			cfg.ResponseMode = conn.mode
		})

		mux.HandleFunc("GET /login/"+name, func(w http.ResponseWriter, r *http.Request) {
			if conn.lax {
				w = laxCookies{w}
			}

			if err := c.StartLogin(w, r, oidcclient.AuthOptions{}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		})
		mux.HandleFunc("/oidc/"+name+"/callback", func(w http.ResponseWriter, r *http.Request) {
			id, err := c.HandleCallback(w, r)
			conn.results <- err

			result := "error: " + fmt.Sprint(err)
			if err == nil {
				result = "subject: " + id.Subject
			}

			_, _ = fmt.Fprintf(w, `<p id="result">%s</p>`, html.EscapeString(result))
		})
	}

	rp.Config.Handler = mux
	rp.StartTLS()
	t.Cleanup(rp.Close)

	allocator, cancel := chromedp.NewExecAllocator(context.Background(),
		append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("ignore-certificate-errors", true))...)
	t.Cleanup(cancel)

	browser, cancel := chromedp.NewContext(allocator)
	t.Cleanup(cancel)
	require.NoError(t, chromedp.Run(browser), "starting Chrome")

	for _, name := range []string{"query", "formpost", "lax"} {
		t.Run(name, func(t *testing.T) {
			conn := connections[name]

			tab, cancel := chromedp.NewContext(browser)
			defer cancel()

			tab, cancel = context.WithTimeout(tab, 30*time.Second)
			defer cancel()

			var (
				result  string
				cookies []*network.Cookie
			)

			require.NoError(t, chromedp.Run(tab,
				chromedp.Navigate(origin+"/login/"+name),
				chromedp.WaitVisible("#username", chromedp.ByID),
				chromedp.SendKeys("#username", "test-user@127.0.0.1", chromedp.ByID),
				chromedp.SendKeys("#password", userPassword, chromedp.ByID),
				chromedp.Submit("#password", chromedp.ByID),
				chromedp.WaitVisible("#result", chromedp.ByID),
				chromedp.Text("#result", &result, chromedp.ByID),
				chromedp.ActionFunc(func(ctx context.Context) error {
					var err error
					cookies, err = network.GetCookies().WithURLs([]string{origin + "/"}).Do(ctx)

					return err //nolint:wrapcheck // test
				}),
			))

			err := <-conn.results
			if conn.want == nil {
				require.NoError(t, err)
				assert.Equal(t, "subject: "+userID, result)
			} else {
				require.ErrorIs(t, err, conn.want, "the browser did not send the cookie")
				assert.True(t, strings.HasPrefix(result, "error: "))
			}

			for _, c := range cookies {
				assert.False(t, strings.HasPrefix(c.Name, "__Host-oidc-"), "binding cookie %s left after the callback", c.Name)
			}
		})
	}
}
