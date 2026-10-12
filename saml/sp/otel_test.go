// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// recordSpans installs an in-memory tracer provider while fn runs. The test
// using it does not call t.Parallel, so no other test emits spans meanwhile.
func recordSpans(fn func()) []sdktrace.ReadOnlySpan {
	previous := otel.GetTracerProvider()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)

	defer otel.SetTracerProvider(previous)

	fn()

	_ = tp.Shutdown(context.Background())

	return rec.Ended()
}

func attrs(s sdktrace.ReadOnlySpan) map[attribute.Key]string {
	out := map[attribute.Key]string{}
	for _, a := range s.Attributes() {
		out[a.Key] = a.Value.Emit()
	}

	return out
}

func TestSpans(t *testing.T) {
	e := newEnv(t, allowSHA1)

	var lr loginResult

	spans := recordSpans(func() {
		lr = begin(t, e, samlsp.LoginOptions{})
		_, err := complete(e, lr, respond(t, lr.requestID, respOpts{}))
		require.NoError(t, err)

		other := begin(t, e, samlsp.LoginOptions{})
		_, err = complete(e, other, respond(t, other.requestID, respOpts{beforeAssertion: func(a *etree.Element) {
			path(a, "Conditions", "AudienceRestriction", "Audience").SetText("https://evil")
		}}))
		require.ErrorIs(t, err, samlsp.ErrAudienceMismatch)

		e.resolver.err = errors.New("db down")
		_, err = complete(e, other, respond(t, other.requestID, respOpts{}))
		require.Error(t, err)
	})

	require.Len(t, spans, 5)

	byName := map[string][]sdktrace.ReadOnlySpan{}
	for _, s := range spans {
		byName[s.Name()] = append(byName[s.Name()], s)
	}

	require.Len(t, byName["samlsp.ServiceProvider.BeginLogin"], 2)
	require.Len(t, byName["samlsp.ServiceProvider.CompleteLogin"], 3)

	for _, s := range spans {
		assert.Equal(t, "github.com/hyperscale-stack/security/saml/sp", s.InstrumentationScope().Name)
	}

	ok := attrs(byName["samlsp.ServiceProvider.CompleteLogin"][0])
	assert.Equal(t, "success", ok[samlsp.AttrOutcome])
	assert.Equal(t, connID, ok[samlsp.AttrConnectionID])
	assert.Equal(t, idpEntity, ok[samlsp.AttrIdPEntityID])
	assert.Equal(t, "true", ok[samlsp.AttrInsecureSHA1])
	assert.Equal(t, "true", ok[samlsp.AttrTransactionConsumed])

	// Refused after the consumption: the operator sees the login is over.
	rejected := byName["samlsp.ServiceProvider.CompleteLogin"][1]
	assert.Equal(t, "rejected", attrs(rejected)[samlsp.AttrOutcome])
	assert.Equal(t, "audience_mismatch", attrs(rejected)[samlsp.AttrReason])
	assert.Equal(t, "true", attrs(rejected)[samlsp.AttrTransactionConsumed])
	assert.Equal(t, codes.Error, rejected.Status().Code)

	failed := attrs(byName["samlsp.ServiceProvider.CompleteLogin"][2])
	assert.Equal(t, "error", failed[samlsp.AttrOutcome])
	assert.Equal(t, "error", failed[samlsp.AttrReason])
	assert.NotContains(t, failed, samlsp.AttrTransactionConsumed, "failed before the consumption")

	// No span carries identity data, RelayState, cookie or request ID.
	for _, s := range spans {
		for _, a := range s.Attributes() {
			v := a.Value.Emit()
			for _, secret := range []string{nameIDValue, lr.relayState, lr.cookie.Value, lr.requestID, "alice@example.com"} {
				assert.False(t, strings.Contains(v, secret), "span attribute %s leaks %q", a.Key, secret)
			}
		}
	}
}

func TestFetchMetadataSpan(t *testing.T) {
	ok := newMetadataServer(t, serveMetadata(idpMetadataSpec{}.render(t)))
	failing := newMetadataServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })

	spans := recordSpans(func() {
		_, err := fetchAt(t, ok, samlsp.FetchOptions{EntityID: idpEntity, Outbound: ok.policy()})
		require.NoError(t, err)

		_, err = fetchAt(t, failing, samlsp.FetchOptions{EntityID: idpEntity, Outbound: failing.policy()})
		require.ErrorIs(t, err, samlsp.ErrMetadataUnavailable)
	})

	var outcomes []map[attribute.Key]string

	for _, s := range spans {
		if s.Name() != "samlsp.FetchMetadata" {
			continue
		}

		a := attrs(s)
		outcomes = append(outcomes, a)

		for _, v := range a {
			assert.NotContains(t, v, "127.0.0.1", "no URL or address on the span")
		}
	}

	require.Len(t, outcomes, 2)
	assert.Equal(t, "success", outcomes[0][samlsp.AttrOutcome])
	assert.Equal(t, "error", outcomes[1][samlsp.AttrOutcome])
	assert.Equal(t, "metadata_unavailable", outcomes[1][samlsp.AttrReason])
}
