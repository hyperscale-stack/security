// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"bytes"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// rule alters how the provider answers one path.
type rule struct {
	// replace answers instead of the provider: status, content type, body.
	replace *reply
	// rewrite edits the provider's response body.
	rewrite func(body []byte) []byte
	// location edits the Location of the provider's redirect.
	location func(*url.URL)
	// delay holds the response back that long.
	delay time.Duration
	// drop lets the provider handle the request, then drops the connection
	// instead of answering: a response lost after the provider committed.
	drop bool
}

// reply is a response the middleware writes itself.
type reply struct {
	status      int
	contentType string
	body        string
}

// recorded is a request the middleware saw.
type recorded struct {
	header http.Header
	form   url.Values
}

// faults wraps the provider: it counts and records requests by path and
// applies the rules the tests install — the network between the relying
// party and the provider, and an attacker on it.
type faults struct {
	next http.Handler

	mu       sync.Mutex
	hits     map[string]int
	requests map[string][]recorded
	rules    map[string]rule
}

func newFaults(next http.Handler) *faults {
	return &faults{next: next, hits: map[string]int{}, requests: map[string][]recorded{}, rules: map[string]rule{}}
}

// set installs r for path, replacing the previous rule.
func (f *faults) set(path string, r rule) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.rules[path] = r
}

// clear removes the rule of path.
func (f *faults) clear(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.rules, path)
}

func (f *faults) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.hits[path]
}

// recordedAt returns the requests path received.
func (f *faults) recordedAt(path string) []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]recorded(nil), f.requests[path]...)
}

func (f *faults) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))

	form, _ := url.ParseQuery(string(body))
	if r.Method == http.MethodGet {
		form = r.URL.Query()
	}

	f.mu.Lock()
	f.hits[r.URL.Path]++
	f.requests[r.URL.Path] = append(f.requests[r.URL.Path], recorded{header: r.Header.Clone(), form: form})
	rl, ruled := f.rules[r.URL.Path]
	f.mu.Unlock()

	if !ruled {
		f.next.ServeHTTP(w, r)

		return
	}

	if rl.replace != nil {
		time.Sleep(rl.delay)
		w.Header().Set("Content-Type", rl.replace.contentType)
		w.WriteHeader(rl.replace.status)
		_, _ = io.WriteString(w, rl.replace.body)

		return
	}

	rec := httptest.NewRecorder()
	f.next.ServeHTTP(rec, r)

	if rl.drop {
		panic(http.ErrAbortHandler) // the connection is dropped, on HTTP/1.1 and HTTP/2
	}

	time.Sleep(rl.delay)

	out := rec.Body.Bytes()
	if rl.rewrite != nil {
		out = rl.rewrite(out)
	}

	maps.Copy(w.Header(), rec.Header())

	if rl.location != nil {
		if loc, err := url.Parse(rec.Header().Get("Location")); err == nil && loc.String() != "" {
			rl.location(loc)
			w.Header().Set("Location", loc.String())
		}
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(rec.Code)
	_, _ = w.Write(out)
}
