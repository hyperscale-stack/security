// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allocatedPerCall returns the bytes f allocates, averaged over n calls.
func allocatedPerCall(n int, f func()) uint64 {
	runtime.GC()

	var before, after runtime.MemStats

	runtime.ReadMemStats(&before)

	for range n {
		f()
	}

	runtime.ReadMemStats(&after)

	return (after.TotalAlloc - before.TotalAlloc) / uint64(n)
}

// TestListParametersParseWithoutAmplification: the space-delimited
// parameters of an unauthenticated authorization request are read without
// allocating per separator — strings.Split allocated a 16-byte header per
// space before any bound applied, about 20 times the request body.
//
// Not parallel: it reads the process-wide allocation counter, averaged over
// several calls so that other goroutines barely count.
func TestListParametersParseWithoutAmplification(t *testing.T) {
	const calls = 8

	spaces := strings.Repeat(" ", 512<<10)
	longPrompt, longList := spaces+"login", spaces+"fr"

	var prompt Prompt

	perPrompt := allocatedPerCall(calls, func() { prompt, _ = parsePrompt(longPrompt) })
	assert.Less(t, perPrompt, uint64(1<<10), "prompt: %d bytes per call", perPrompt)
	assert.True(t, prompt.Login, "the whole value is read")

	// Within the length bound: only the values kept are allocated.
	bounded := strings.Repeat(" ", maxListLength-2) + "fr"

	var kept []string

	perList := allocatedPerCall(calls, func() { kept = tokens(bounded) })
	assert.Less(t, perList, uint64(1<<10), "bounded list: %d bytes per call", perList)
	assert.Equal(t, []string{"fr"}, kept)

	perOversized := allocatedPerCall(calls, func() { kept = tokens(longList) })
	assert.Less(t, perOversized, uint64(1<<10), "oversized list: %d bytes per call", perOversized)
	assert.Nil(t, kept, "an oversized list is ignored")
}

// TestCheckRedirectionRefusesRepeatedUnredirectableParameters pins the
// provider's own refusal of a client_id, redirect_uri or response_mode
// included more than once with a value (RFC 6749 §3.1), with a bare 400:
// defense in depth, since the oauth2 core refuses them before any
// extension runs, so no request through the handler reaches it. An empty
// occurrence is no repetition.
func TestCheckRedirectionRefusesRepeatedUnredirectableParameters(t *testing.T) {
	t.Parallel()

	for _, name := range unredirectableParameters {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			form := url.Values{paramRedirectURI: {"https://client.example/cb"}}

			form[name] = []string{"https://client.example/cb", "https://client.example/cb"}
			require.ErrorIs(t, checkRedirection(form), oauth2.ErrUnredirectableRequest)

			form[name] = []string{"", "https://client.example/cb"}
			assert.NoError(t, checkRedirection(form))
		})
	}
}
