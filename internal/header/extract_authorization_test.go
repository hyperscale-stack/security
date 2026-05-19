// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package header

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAuthorizationValue(t *testing.T) {
	creds, ok := ExtractAuthorizationValue("Basic", "Basic Zm9vOnBhc3M=")
	assert.True(t, ok)
	assert.Equal(t, "Zm9vOnBhc3M=", creds)
}

func TestExtractAuthorizationValueWithBadType(t *testing.T) {
	creds, ok := ExtractAuthorizationValue("Digest", "Basic Zm9vOnBhc3M=")
	assert.False(t, ok)
	assert.Empty(t, creds)
}

func BenchmarkExtractAuthorizationValue(b *testing.B) {
	// run the Fib function b.N times
	for n := 0; n < b.N; n++ {
		ExtractAuthorizationValue("Basic", "Basic Zm9vOnBhc3M=")
	}
}
