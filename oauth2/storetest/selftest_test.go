// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package storetest_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/storetest"
	"github.com/stretchr/testify/require"
)

// lieEnv names the lie TestHelperLyingStore runs the suite against; the
// helper skips while it is unset.
const lieEnv = "STORETEST_HELPER_LIE"

// forgetAfter is how long a forgetting liar keeps what it forgets: a
// second, as a store whose TTLs are a second — or a thousand times too
// short — would.
const forgetAfter = time.Second

// liar is the in-memory store with one deliberate defect, named by lie:
// its lookups misreport one field of a token record, or it forgets a
// consumed code, a rotated refresh token (at rotation, or at lookup) or a
// revoked family after forgetAfter. The conformance suite must fail on every one of them.
type liar struct {
	*memory.Store

	lie   string
	mu    sync.Mutex
	since map[string]time.Time // when a code was consumed, a token rotated, a family revoked
}

func newLiar(lie string) *liar {
	return &liar{Store: memory.New(), lie: lie, since: map[string]time.Time{}}
}

// record notes that key happened now; forgotten reports whether key
// happened more than forgetAfter ago, for the lie that forgets it.
func (l *liar) record(lie, key string) {
	if l.lie != lie {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.since[key] = time.Now()
}

func (l *liar) forgotten(lie, key string) bool {
	if l.lie != lie {
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	at, ok := l.since[key]

	return ok && time.Since(at) > forgetAfter
}

func (l *liar) ConsumeAuthorizationCode(ctx context.Context, hash string) (*oauth2.AuthorizationCode, error) {
	if l.forgotten("forget-code", hash) {
		return nil, oauth2.ErrCodeAlreadyUsed // an unknown code: no replay to report
	}

	code, err := l.Store.ConsumeAuthorizationCode(ctx, hash)
	if err == nil {
		l.record("forget-code", hash)
	}

	return code, err
}

func (l *liar) RotateRefreshToken(ctx context.Context, oldHash string, next *oauth2.TokenPair) error {
	if l.forgotten("forget-rotated", oldHash) {
		return oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
	}

	err := l.Store.RotateRefreshToken(ctx, oldHash, next)
	if err == nil {
		l.record("forget-rotated", oldHash)
		l.record("forget-consumed-token", oldHash)
	}

	return err
}

func (l *liar) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	err := l.Store.RevokeRefreshFamily(ctx, familyID)
	if err == nil {
		l.record("forget-revoked", familyID)
	}

	return err
}

// SaveTokenPair issues a pair of a forgotten family into a fresh one: what
// a store that lost the family's revoked state does.
func (l *liar) SaveTokenPair(ctx context.Context, pair *oauth2.TokenPair) error {
	if pair != nil && l.forgotten("forget-revoked", pair.Access.FamilyID) {
		reborn := *pair
		reborn.Access.FamilyID += "/forgotten"

		if pair.Refresh != nil {
			refresh := *pair.Refresh
			refresh.FamilyID = reborn.Access.FamilyID
			reborn.Refresh = &refresh
		}

		return l.Store.SaveTokenPair(ctx, &reborn)
	}

	return l.Store.SaveTokenPair(ctx, pair)
}

func (l *liar) LookupAccessToken(ctx context.Context, hash string) (*oauth2.AccessToken, error) {
	at, err := l.Store.LookupAccessToken(ctx, hash)
	if err != nil {
		return at, err
	}

	switch l.lie {
	case "expires":
		at.ExpiresAt = at.ExpiresAt.Add(100 * 365 * 24 * time.Hour)
	case "issued-at":
		at.IssuedAt = at.IssuedAt.Add(-time.Hour)
	case "client":
		at.ClientID = "another-client"
	case "scope":
		at.Scope += " admin"
	case "audience":
		at.Audience = "another-api"
	}

	return at, nil
}

func (l *liar) LookupRefreshToken(ctx context.Context, hash string) (*oauth2.RefreshToken, error) {
	if l.forgotten("forget-consumed-token", hash) {
		return nil, oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
	}

	rt, err := l.Store.LookupRefreshToken(ctx, hash)
	if err != nil {
		return rt, err
	}

	switch l.lie {
	case "expires":
		rt.ExpiresAt = rt.ExpiresAt.Add(100 * 365 * 24 * time.Hour)
	case "client":
		rt.ClientID = "another-client"
	case "subject":
		rt.Subject = "mallory"
	case "consumed":
		rt.Consumed = !rt.Consumed
	case "family-issued-at":
		rt.FamilyIssuedAt = rt.IssuedAt
	}

	return rt, nil
}

// TestHelperLyingStore is the process TestConformanceCatchesLyingStores
// runs: the conformance suite against the liar its environment names.
func TestHelperLyingStore(t *testing.T) {
	lie := os.Getenv(lieEnv)
	if lie == "" {
		t.Skip("the helper process of TestConformanceCatchesLyingStores")
	}

	storetest.RunConformance(t, func() oauth2.Storage { return newLiar(lie) })
}

// TestConformanceCatchesLyingStores runs the suite, in a process of its
// own, against stores lying about one security field of a token record or
// forgetting what they must retain (the gaps of the audit's F-23), and
// asserts that the case pinning it fails, naming the defect. The honest
// store passes, so every failure is the lie's.
func TestConformanceCatchesLyingStores(t *testing.T) {
	t.Parallel()

	const (
		records   = "TokenRecordsRoundTrip"
		retention = "RetainedOverTime"
	)

	for _, c := range []struct {
		lie, caseName, want string
	}{
		{"none", records, ""},
		{"none", retention, ""},
		{"expires", records, "fields [ExpiresAt] differ"},
		{"issued-at", records, "fields [IssuedAt] differ"},
		{"client", records, "fields [ClientID] differ"},
		{"scope", records, "fields [Scope] differ"},
		{"audience", records, "fields [Audience] differ"},
		{"subject", records, "fields [Subject] differ"},
		{"consumed", records, "fields [Consumed] differ"},
		{"family-issued-at", records, "fields [FamilyIssuedAt] differ"},
		{"forget-code", retention, "replay the consumed code later"},
		{"forget-rotated", retention, "reuse the rotated refresh token later"},
		{"forget-consumed-token", retention, "lookup refresh token rt-retained-0"},
		{"forget-revoked", retention, "issue into the family revoked before issuance, later"},
	} {
		t.Run(c.lie+"/"+c.caseName, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()

			cmd := exec.CommandContext(ctx, os.Args[0], //nolint:gosec // the test binary itself
				"-test.run=^TestHelperLyingStore$/^"+c.caseName+"$", "-test.v", "-test.count=1")
			cmd.Env = append(os.Environ(), lieEnv+"="+c.lie)

			out, err := cmd.CombinedOutput()
			output := string(out)

			require.True(t, strings.Contains(output, "=== RUN   TestHelperLyingStore/"+c.caseName),
				"the helper must run the case %s:\n%s", c.caseName, output)

			if c.want == "" {
				require.NoError(t, err, "the honest store must pass %s:\n%s", c.caseName, output)

				return
			}

			var exit *exec.ExitError

			require.True(t, errors.As(err, &exit), "the suite passed a store that lies (%s):\n%s", c.lie, output)
			require.Contains(t, output, "--- FAIL: TestHelperLyingStore/"+c.caseName)
			require.Contains(t, output, c.want)
		})
	}
}
