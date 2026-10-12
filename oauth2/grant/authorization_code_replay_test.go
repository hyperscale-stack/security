// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"context"
	"errors"
	"maps"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/pkce"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// replayStore decorates the memory store for the code-replay tests. It
// counts the family revocations, records the deadline of the context each
// one runs on, can fail them, honors that context like a real backend, can
// force the result of a code consumption, runs afterConsume after every
// one, and runs beforeSave once, right before the first SaveTokenPair it
// records — a replay landing between a code's consumption and the
// issuance of its tokens. It is safe for concurrent use once configured.
type replayStore struct {
	*memory.Store

	consumeErr   error
	afterConsume func()
	revokeErr    error
	revokes      atomic.Int32

	mu         sync.Mutex
	beforeSave func()
	saved      []oauth2.TokenPair
	deadlines  []time.Time // zero when a revocation context had none
}

func (s *replayStore) ConsumeAuthorizationCode(ctx context.Context, hash string) (*oauth2.AuthorizationCode, error) {
	if s.consumeErr != nil {
		return nil, s.consumeErr
	}

	code, err := s.Store.ConsumeAuthorizationCode(ctx, hash)

	if s.afterConsume != nil {
		s.afterConsume()
	}

	return code, err
}

func (s *replayStore) SaveTokenPair(ctx context.Context, pair *oauth2.TokenPair) error {
	s.mu.Lock()
	s.saved = append(s.saved, *pair)
	hook := s.beforeSave
	s.beforeSave = nil
	s.mu.Unlock()

	if hook != nil {
		hook()
	}

	return s.Store.SaveTokenPair(ctx, pair)
}

func (s *replayStore) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	s.revokes.Add(1)

	deadline, _ := ctx.Deadline()

	s.mu.Lock()
	s.deadlines = append(s.deadlines, deadline)
	s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	if s.revokeErr != nil {
		return s.revokeErr
	}

	return s.Store.RevokeRefreshFamily(ctx, familyID)
}

// revocationDeadlines returns the deadline of each family revocation's
// context, zero for none.
func (s *replayStore) revocationDeadlines() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]time.Time(nil), s.deadlines...)
}

// savedPairs returns the pairs the grant tried to persist.
func (s *replayStore) savedPairs() []oauth2.TokenPair {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]oauth2.TokenPair(nil), s.saved...)
}

// codeRequest saves the authorization code raw — S256 PKCE, issued to the
// test client, valid for 10 minutes — into store, and returns the /token
// request redeeming it under the BCP profile.
func codeRequest(t *testing.T, store oauth2.Storage, raw string) grant.Request {
	t.Helper()

	now := time.Now()

	require.NoError(t, store.SaveAuthorizationCode(t.Context(), &oauth2.AuthorizationCode{
		Code: raw, CodeHash: oauth2.HashToken(nil, raw),
		ClientID: clientID, Subject: subject, RedirectURI: redirectURI, Scope: "read:mail",
		CodeChallenge: codeChallenge, CodeChallengeMethod: string(pkce.MethodS256),
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Issuer: "https://auth.example",
	}))

	return grant.Request{
		Client:   newClient(),
		Form:     url.Values{"code": {raw}, "redirect_uri": {redirectURI}, "code_verifier": {codeVerifier}},
		Issuer:   "https://auth.example",
		Audience: "api",
		Now:      now,
		Profile:  oauth2.Profile20BCP,
	}
}

// withForm returns a request change editing a copy of the form.
func withForm(edit func(url.Values)) func(grant.Request) grant.Request {
	return func(req grant.Request) grant.Request {
		req.Form = maps.Clone(req.Form)
		edit(req.Form)

		return req
	}
}

// requirePairUsable asserts that both tokens of pair still work.
func requirePairUsable(t *testing.T, store oauth2.Storage, pair oauth2.TokenPair) {
	t.Helper()

	_, err := store.LookupAccessToken(t.Context(), pair.Access.TokenHash)
	require.NoError(t, err, "access token")

	if pair.Refresh == nil {
		return
	}

	rt, err := store.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
	require.NoError(t, err, "refresh token")
	assert.False(t, rt.Consumed, "refresh token")
}

// requirePairRevoked asserts that no token of pair works any more: its
// family is revoked.
func requirePairRevoked(t *testing.T, store oauth2.Storage, pair oauth2.TokenPair) {
	t.Helper()

	_, err := store.LookupAccessToken(t.Context(), pair.Access.TokenHash)
	require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked, "access token")

	if pair.Refresh == nil {
		return
	}

	rt, err := store.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
	require.NoError(t, err, "refresh token")
	assert.True(t, rt.Consumed, "refresh token")
}

// requirePairAbsent asserts that nothing of pair was persisted: both
// lookups fail as for tokens never issued, not as for revoked ones.
func requirePairAbsent(t *testing.T, store oauth2.Storage, pair oauth2.TokenPair) {
	t.Helper()

	_, err := store.LookupAccessToken(t.Context(), pair.Access.TokenHash)
	require.Error(t, err, "access token")
	assert.NotErrorIs(t, err, oauth2.ErrTokenFamilyRevoked, "access token never persisted")

	if pair.Refresh == nil {
		return
	}

	_, err = store.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
	require.Error(t, err, "refresh token never persisted")
}

// TestAuthorizationCodeReplayRevokesIssuedTokens is the reproduction of
// issue #80: a code is exchanged, then replayed with the same proof. The
// replay is refused, and the tokens the first exchange issued are revoked
// (RFC 6749 §4.1.2).
func TestAuthorizationCodeReplayRevokesIssuedTokens(t *testing.T) {
	t.Parallel()

	store := &replayStore{Store: memory.New()}
	hooks := &hookRecorder{}
	cfg := rotatingConfig(store, hooks)
	g := grant.NewAuthorizationCode(cfg)
	req := codeRequest(t, store, "replayed-code")

	first, err := g.Handle(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, first.Pair.Refresh)
	requirePairUsable(t, store, first.Pair)

	resp, err := g.Handle(t.Context(), req)
	assert.Nil(t, resp)
	assert.Same(t, oauth2.ErrCodeAlreadyUsed, err, "the replay gets the bare refusal")

	assert.Equal(t, int32(1), store.revokes.Load())
	assert.Empty(t, hooks.errs)
	requirePairRevoked(t, store, first.Pair)

	// The refresh token cannot be exchanged any more either.
	_, err = grant.NewRefreshToken(cfg).Handle(t.Context(), refreshReq(first.Pair.Refresh.Token, oauth2.Profile20BCP))
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

// TestAuthorizationCodeReplayRevokesRotatedTokens replays a code after its
// refresh token was rotated: the rotation stayed in the code's family, so
// the replay revokes it too.
func TestAuthorizationCodeReplayRevokesRotatedTokens(t *testing.T) {
	t.Parallel()

	store := &replayStore{Store: memory.New()}
	cfg := rotatingConfig(store, &hookRecorder{})
	g := grant.NewAuthorizationCode(cfg)
	req := codeRequest(t, store, "rotated-code")

	first, err := g.Handle(t.Context(), req)
	require.NoError(t, err)

	rotated, err := grant.NewRefreshToken(cfg).Handle(t.Context(), refreshReq(first.Pair.Refresh.Token, oauth2.Profile20BCP))
	require.NoError(t, err)
	require.NotNil(t, rotated.Pair.Refresh, "the BCP profile rotates")
	requirePairUsable(t, store, rotated.Pair)

	_, err = g.Handle(t.Context(), req)
	assert.Same(t, oauth2.ErrCodeAlreadyUsed, err)

	requirePairRevoked(t, store, first.Pair)
	requirePairRevoked(t, store, rotated.Pair)
}

// TestAuthorizationCodeReplayBeforeIssuanceRefusesTheExchange lands a
// proven replay between the first exchange's consumption of the code and
// the issuance of its tokens: the family, derived from the code before it
// was consumed, is revoked first, so the first exchange issues nothing and
// answers invalid_grant.
func TestAuthorizationCodeReplayBeforeIssuanceRefusesTheExchange(t *testing.T) {
	t.Parallel()

	store := &replayStore{Store: memory.New()}
	hooks := &hookRecorder{}
	g := grant.NewAuthorizationCode(rotatingConfig(store, hooks))
	req := codeRequest(t, store, "raced-code")

	var replayErr error

	store.beforeSave = func() { _, replayErr = g.Handle(t.Context(), req) }

	resp, err := g.Handle(t.Context(), req)
	assert.Nil(t, resp)
	require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))

	assert.Same(t, oauth2.ErrCodeAlreadyUsed, replayErr)
	assert.Equal(t, int32(1), store.revokes.Load())
	assert.Empty(t, hooks.errs, "the refusals are no server errors")

	saved := store.savedPairs()
	require.Len(t, saved, 1, "only the first exchange reached issuance")
	requirePairAbsent(t, store, saved[0])
}

// TestAuthorizationCodeReplayRevokesAccessOnlyIssuance covers a grant
// without a refresh-token generator: the lone access token is in the
// code's family and revoked with it.
func TestAuthorizationCodeReplayRevokesAccessOnlyIssuance(t *testing.T) {
	t.Parallel()

	store := &replayStore{Store: memory.New()}
	g := grant.NewAuthorizationCode(grant.Config{Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour})
	req := codeRequest(t, store, "access-only-code")

	first, err := g.Handle(t.Context(), req)
	require.NoError(t, err)
	require.Nil(t, first.Pair.Refresh)
	assert.NotEmpty(t, first.Pair.Access.FamilyID)

	_, err = g.Handle(t.Context(), req)
	assert.Same(t, oauth2.ErrCodeAlreadyUsed, err)
	requirePairRevoked(t, store, first.Pair)
}

// TestAuthorizationCodeUnprovenReplayRevokesNothing replays a consumed code
// with requests that could not have redeemed it — another client, a
// missing or wrong proof, another redirect_uri, an expired code, a client
// no longer allowed the grant — and an unknown code: each one revokes
// nothing (OAuth 2.1 §4.1.3, §7.5.3) and gets the very answer of any
// replay, so the response tells nothing about which check failed. A
// request that would have been accepted revokes.
func TestAuthorizationCodeUnprovenReplayRevokesNothing(t *testing.T) {
	t.Parallel()

	store := &replayStore{Store: memory.New()}
	hooks := &hookRecorder{}
	g := grant.NewAuthorizationCode(rotatingConfig(store, hooks))
	req := codeRequest(t, store, "unproven-code")

	first, err := g.Handle(t.Context(), req)
	require.NoError(t, err)

	cases := []struct {
		name   string
		replay func(grant.Request) grant.Request
	}{
		{"another confidential client", func(r grant.Request) grant.Request {
			r.Client = &oauth2.DefaultClient{
				GrantTypeValues: allGrantTypes,
				IDValue:         "client-2", Secret: "secret-2", TypeValue: oauth2.ClientConfidential,
				RedirectURIValues: []string{redirectURI},
			}

			return r
		}},
		{"no code_verifier", withForm(func(f url.Values) { f.Del("code_verifier") })},
		{"a well-formed wrong code_verifier", withForm(func(f url.Values) { f.Set("code_verifier", wellFormedWrongVerifier) })},
		{"a malformed code_verifier", withForm(func(f url.Values) { f.Set("code_verifier", "x") })},
		{"another redirect_uri", withForm(func(f url.Values) { f.Set("redirect_uri", "https://attacker.example/cb") })},
		{"an expired code", func(r grant.Request) grant.Request {
			r.Now = r.Now.Add(time.Hour)

			return r
		}},
		{"a client no longer allowed authorization_code", func(r grant.Request) grant.Request {
			r.Client = &oauth2.DefaultClient{
				IDValue: clientID, Secret: clientSecret, TypeValue: oauth2.ClientConfidential,
				RedirectURIValues: []string{redirectURI}, GrantTypeValues: []string{"client_credentials"},
			}

			return r
		}},
		{"an unknown code", withForm(func(f url.Values) { f.Set("code", "never-issued") })},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := g.Handle(t.Context(), tc.replay(req))
			assert.Nil(t, resp)
			assert.Same(t, oauth2.ErrCodeAlreadyUsed, err, "the answer of any replay: no oracle")

			assert.Zero(t, store.revokes.Load())
			assert.Empty(t, hooks.errs)
			requirePairUsable(t, store, first.Pair)
		})
	}

	// The positive control: the same request as the first exchange.
	_, err = g.Handle(t.Context(), req)
	assert.Same(t, oauth2.ErrCodeAlreadyUsed, err)
	assert.Equal(t, int32(1), store.revokes.Load())
	requirePairRevoked(t, store, first.Pair)
}

// TestAuthorizationCodeReplayWithoutRecordRevokesNothing covers a store
// reporting a replay without the retained record — a CodeReplayError
// without one, or a typed nil: the replay cannot be validated, so the
// grant refuses it like an unknown code and revokes nothing.
func TestAuthorizationCodeReplayWithoutRecordRevokesNothing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
	}{
		{"no record", &oauth2.CodeReplayError{}},
		{"typed nil", (*oauth2.CodeReplayError)(nil)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &replayStore{Store: memory.New(), consumeErr: tc.err}
			g := grant.NewAuthorizationCode(rotatingConfig(store, &hookRecorder{}))

			resp, err := g.Handle(t.Context(), codeRequest(t, store, "recordless-code"))
			assert.Nil(t, resp)
			require.ErrorIs(t, err, oauth2.ErrCodeAlreadyUsed)
			assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
			assert.Zero(t, store.revokes.Load())
		})
	}
}

// TestAuthorizationCodeReplayRevocationFailureIsReported fails the
// revocation a proven replay triggers: the client still gets the refusal,
// the failure reaches the grant's error hook once, and the retained code
// lets the next proven replay revoke the family.
func TestAuthorizationCodeReplayRevocationFailureIsReported(t *testing.T) {
	t.Parallel()

	store := &replayStore{Store: memory.New()}
	hooks := &hookRecorder{}
	g := grant.NewAuthorizationCode(rotatingConfig(store, hooks))
	req := codeRequest(t, store, "unrevoked-code")

	first, err := g.Handle(t.Context(), req)
	require.NoError(t, err)

	family := first.Pair.Access.FamilyID
	store.revokeErr = revocationFailure(family)

	_, err = g.Handle(t.Context(), req)
	assert.Same(t, oauth2.ErrCodeAlreadyUsed, err, "the client gets the refusal either way")

	require.Len(t, hooks.errs, 1, "one report per failed revocation")

	got := hooks.errs[0]
	assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(got))
	assert.ErrorContains(t, got, "revoke token family failed after authorization code replay")
	assert.ErrorIs(t, got, oauth2.ErrTokenFamilyRevocationFailed)
	assert.ErrorIs(t, got, errBackendDown)
	assert.ErrorContains(t, errors.Unwrap(got), family, "the cause names the family")
	assert.NotErrorIs(t, got, oauth2.ErrCodeAlreadyUsed, "the report counts the revocation, not the replay")
	requirePairUsable(t, store, first.Pair)

	// The backend recovers: the next proven replay revokes, quietly.
	store.revokeErr = nil

	_, err = g.Handle(t.Context(), req)
	assert.Same(t, oauth2.ErrCodeAlreadyUsed, err)
	requirePairRevoked(t, store, first.Pair)
	assert.Len(t, hooks.errs, 1, "a successful revocation is not reported")
}

// TestAuthorizationCodeReplayRevocationDetachedFromRequest cancels the
// replaying request right after its code is consumed — a client hanging
// up: the revocation still runs, on a context detached from the request
// and bounded by the detached revocation timeout (10s).
func TestAuthorizationCodeReplayRevocationDetachedFromRequest(t *testing.T) {
	t.Parallel()

	store := &replayStore{Store: memory.New()}
	hooks := &hookRecorder{}
	g := grant.NewAuthorizationCode(rotatingConfig(store, hooks))
	req := codeRequest(t, store, "hung-up-code")

	first, err := g.Handle(t.Context(), req)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	store.afterConsume = cancel

	_, err = g.Handle(ctx, req)
	assert.Same(t, oauth2.ErrCodeAlreadyUsed, err)
	require.Error(t, ctx.Err(), "the request was canceled")

	assert.Equal(t, int32(1), store.revokes.Load())

	deadlines := store.revocationDeadlines()
	require.Len(t, deadlines, 1)
	require.False(t, deadlines[0].IsZero(), "the detached revocation is bounded")
	assert.WithinDuration(t, time.Now(), deadlines[0], 10*time.Second, "by the detached revocation timeout")
	assert.Empty(t, hooks.errs)
	requirePairRevoked(t, store, first.Pair)
}

// TestAuthorizationCodeReplayOnlyRevokesItsOwnFamily exchanges two codes of
// the same client: each opens a family of its own, and replaying one
// leaves the other untouched.
func TestAuthorizationCodeReplayOnlyRevokesItsOwnFamily(t *testing.T) {
	t.Parallel()

	store := &replayStore{Store: memory.New()}
	g := grant.NewAuthorizationCode(rotatingConfig(store, &hookRecorder{}))
	reqA := codeRequest(t, store, "code-a")
	reqB := codeRequest(t, store, "code-b")

	a, err := g.Handle(t.Context(), reqA)
	require.NoError(t, err)

	b, err := g.Handle(t.Context(), reqB)
	require.NoError(t, err)

	assert.Len(t, a.Pair.Access.FamilyID, 22)
	assert.Len(t, b.Pair.Access.FamilyID, 22)
	assert.NotEqual(t, a.Pair.Access.FamilyID, b.Pair.Access.FamilyID)

	_, err = g.Handle(t.Context(), reqA)
	assert.Same(t, oauth2.ErrCodeAlreadyUsed, err)

	requirePairRevoked(t, store, a.Pair)
	requirePairUsable(t, store, b.Pair)
}

// TestAuthorizationCodeConcurrentRedemption exchanges one code from 16
// goroutines at once. Whatever the schedule, at most one exchange
// succeeds, every other one is an invalid_grant, every loser revokes the
// code's family, and a winner's tokens end up revoked.
func TestAuthorizationCodeConcurrentRedemption(t *testing.T) {
	t.Parallel()

	store := &replayStore{Store: memory.New()}
	g := grant.NewAuthorizationCode(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
		AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour,
	})
	req := codeRequest(t, store, "contended-code")

	const n = 16

	resps := make([]*grant.Response, n)
	errs := make([]error, n)

	var wg sync.WaitGroup

	start := make(chan struct{})

	for i := range n {
		wg.Go(func() {
			<-start

			resps[i], errs[i] = g.Handle(context.Background(), req)
		})
	}

	close(start)
	wg.Wait()

	wins := 0

	for i, err := range errs {
		if err == nil {
			wins++

			requirePairRevoked(t, store, resps[i].Pair)

			continue
		}

		assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err), "%v", err)
	}

	assert.LessOrEqual(t, wins, 1)
	assert.Equal(t, int32(n-1), store.revokes.Load(), "every replay proved possession")
}

// TestLegacyPasswordIssuesFreshFamilies: the password grant has no code to
// derive a family from, so each exchange opens a new random one.
func TestLegacyPasswordIssuesFreshFamilies(t *testing.T) {
	t.Parallel()

	g := grant.NewLegacyPassword(grant.Config{
		Storage: newStore(), AccessTokens: newAccessGen(),
		RefreshTokens: newRefreshGen(), AccessTTL: time.Hour, RefreshTTL: time.Hour,
	}, fakeROVerifier{subject: subject})

	req := grant.Request{Client: newClient(), Form: passwordForm("alice", "s3cr3t", ""), Now: time.Now()}

	a, err := g.Handle(t.Context(), req)
	require.NoError(t, err)

	b, err := g.Handle(t.Context(), req)
	require.NoError(t, err)

	assert.NotEmpty(t, a.Pair.Access.FamilyID)
	assert.NotEqual(t, a.Pair.Access.FamilyID, b.Pair.Access.FamilyID)
	assert.Equal(t, a.Pair.Access.FamilyID, a.Pair.Refresh.FamilyID)
}
