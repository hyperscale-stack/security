// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCodeReplayErrorMatchesCodeAlreadyUsed pins what a store's replay
// error looks like to its callers, bare or wrapped with %w: the
// invalid_grant ErrCodeAlreadyUsed for errors.Is, IsCode and the error
// text, and the retained record for errors.As.
func TestCodeReplayErrorMatchesCodeAlreadyUsed(t *testing.T) {
	t.Parallel()

	record := &oauth2.AuthorizationCode{CodeHash: "hash", ClientID: "client"}
	replay := &oauth2.CodeReplayError{Record: record}

	for name, err := range map[string]error{
		"bare":    replay,
		"wrapped": fmt.Errorf("store: consume: %w", replay),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.ErrorIs(t, err, oauth2.ErrCodeAlreadyUsed)
			require.ErrorIs(t, err, security.ErrInvalidCredentials, "the core sentinel stays reachable")
			assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
			assert.Contains(t, err.Error(), oauth2.ErrCodeAlreadyUsed.Error())

			var got *oauth2.CodeReplayError

			require.ErrorAs(t, err, &got)
			assert.Same(t, record, got.Record)
		})
	}

	assert.Equal(t, oauth2.ErrCodeAlreadyUsed.Error(), replay.Error())
	assert.Same(t, oauth2.ErrCodeAlreadyUsed, errors.Unwrap(replay))
}

// TestCodeAlreadyUsedIsNoReplay: the bare sentinel — what a store returns
// for an unknown code — carries no record to revoke from.
func TestCodeAlreadyUsedIsNoReplay(t *testing.T) {
	t.Parallel()

	var replay *oauth2.CodeReplayError

	assert.False(t, errors.As(oauth2.ErrCodeAlreadyUsed, &replay))
}
