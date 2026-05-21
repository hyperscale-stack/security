// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec_test

import (
	"net/http"
	"testing"

	connectrpcsec "github.com/hyperscale-stack/security/connectrpc"
	"github.com/stretchr/testify/assert"
)

func TestCarrierReads(t *testing.T) {
	t.Parallel()

	hdr := http.Header{"Authorization": {"Bearer one", "Bearer two"}}
	carrier := connectrpcsec.NewCarrier(hdr)

	// Get returns the first value; lookups are case-insensitive.
	assert.Equal(t, "Bearer one", carrier.Get("Authorization"))
	assert.Equal(t, "Bearer one", carrier.Get("authorization"))

	// Values returns every value.
	assert.Equal(t, []string{"Bearer one", "Bearer two"}, carrier.Values("authorization"))

	// Absent keys yield the zero values.
	assert.Empty(t, carrier.Get("X-Absent"))
	assert.Nil(t, carrier.Values("X-Absent"))
}

func TestCarrierWritesResponseHeader(t *testing.T) {
	t.Parallel()

	carrier := connectrpcsec.NewCarrier(http.Header{})

	carrier.Set("X-Trace", "first")
	carrier.Set("X-Trace", "second") // Set replaces.
	carrier.Add("X-Trace", "third")  // Add appends.

	assert.Equal(t, []string{"second", "third"}, carrier.ResponseHeader().Values("X-Trace"))
}

func TestCarrierNilHeader(t *testing.T) {
	t.Parallel()

	carrier := connectrpcsec.NewCarrier(nil)

	assert.Empty(t, carrier.Get("Authorization"))
	assert.Nil(t, carrier.Values("Authorization"))

	// Writes still work against the staged header.
	carrier.Set("X-Trace", "value")
	assert.Equal(t, "value", carrier.ResponseHeader().Get("X-Trace"))
}
