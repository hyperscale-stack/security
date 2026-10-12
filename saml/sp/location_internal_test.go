// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSameAuthority(t *testing.T) {
	t.Parallel()

	parse := func(s string) *url.URL {
		u, err := url.Parse(s)
		require.NoError(t, err)

		return u
	}

	cases := []struct {
		host, acs string
		want      bool
	}{
		{"sp.example.com", "https://sp.example.com/acs", true},
		{"SP.EXAMPLE.COM", "https://sp.example.com/acs", true},
		{"sp.example.com:443", "https://sp.example.com/acs", true},
		{"sp.example.com", "https://sp.example.com:443/acs", true},
		{"sp.example.com:8443", "https://sp.example.com:8443/acs", true},
		{"localhost:8084", "http://localhost:8084/acs", true},
		{"localhost", "http://localhost:80/acs", true},
		{"[::1]:8443", "https://[::1]:8443/acs", true},
		{"[::1]", "https://[::1]/acs", true},
		{"[::1]:443", "https://[::1]/acs", true},
		{"127.0.0.1:8084", "http://127.0.0.1:8084/acs", true},

		{"", "https://sp.example.com/acs", false},
		{"sp.example.com:8443", "https://sp.example.com/acs", false},
		{"sp.example.com:80", "https://sp.example.com/acs", false},
		{"sp.example.com", "https://sp.example.com:8443/acs", false},
		{"sp.example.com.", "https://sp.example.com/acs", false},
		{"other.example.com", "https://sp.example.com/acs", false},
		{"sp.example.com:", "https://sp.example.com:8443/acs", false},
		{"[::2]:8443", "https://[::1]:8443/acs", false},
		{"[::1", "https://[::1]/acs", false},
		{"::1", "https://[::1]/acs", false},
		{"sp.example.com:443:443", "https://sp.example.com/acs", false},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.want, sameAuthority(tc.host, parse(tc.acs)), "%q vs %s", tc.host, tc.acs)
	}
}
