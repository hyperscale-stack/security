// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURIValidate(t *testing.T) {
	valid := [][]string{
		{
			// Exact match
			"http://localhost:14000/appauth",
			"http://localhost:14000/appauth",
			"http://localhost:14000/appauth",
		},
		{
			// Trailing slash
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/",
		},
		{
			// Exact match with trailing slash
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/",
		},
		{
			// Subpath
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/interface/implementation",
			"http://www.google.com/myapp/interface/implementation",
		},
		{
			// Subpath with trailing slash
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/interface/implementation",
			"http://www.google.com/myapp/interface/implementation",
		},
		{
			// Subpath with things that are close to path traversals, but aren't
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/.../..implementation../...",
			"http://www.google.com/myapp/.../..implementation../...",
		},
		{
			// If the allowed basepath contains path traversals, allow them?
			"http://www.google.com/traversal/../allowed",
			"http://www.google.com/traversal/../allowed/with/subpath",
			"http://www.google.com/allowed/with/subpath",
		},
		{
			// Backslashes
			"https://mysafewebsite.com/secure/redirect",
			"https://mysafewebsite.com/secure/redirect/\\../\\../\\../evil",
			"https://mysafewebsite.com/secure/redirect/%5C../%5C../%5C../evil",
		},
		{
			// Backslashes
			"https://mysafewebsite.com/secure/redirect",
			"https://mysafewebsite.com/secure/redirect/\\..\\../\\../evil",
			"https://mysafewebsite.com/secure/redirect/%5C..%5C../%5C../evil",
		},
		{
			// Query string must be kept
			"http://www.google.com/myapp/redir",
			"http://www.google.com/myapp/redir?a=1&b=2",
			"http://www.google.com/myapp/redir?a=1&b=2",
		},
	}
	for _, v := range valid {
		realRedirectURI, err := ValidateURI(v[0], v[1])
		assert.NoError(t, err)
		assert.Equal(t, v[2], realRedirectURI)
	}

	invalid := [][]string{
		{
			// Doesn't satisfy base path
			"http://localhost:14000/appauth",
			"http://localhost:14000/app",
		},
		{
			// Doesn't satisfy base path
			"http://localhost:14000/app/",
			"http://localhost:14000/app",
		},
		{
			// Not a subpath of base path
			"http://localhost:14000/appauth",
			"http://localhost:14000/appauthmodifiedpath",
		},
		{
			// Host mismatch
			"http://www.google.com/myapp",
			"http://www2.google.com/myapp",
		},
		{
			// Scheme mismatch
			"http://www.google.com/myapp",
			"https://www.google.com/myapp",
		},
		{
			// Path traversal
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/..",
		},
		{
			// Embedded path traversal
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/../test",
		},
		{
			// Not a subpath
			"http://www.google.com/myapp",
			"http://www.google.com/myapp../test",
		},
		{
			// Backslashes
			"https://mysafewebsite.com/secure/redirect",
			"https://mysafewebsite.com/secure%2fredirect/../evil",
		},
	}
	for _, v := range invalid {
		if _, err := ValidateURI(v[0], v[1]); err == nil {
			t.Errorf("Expected ValidateURI(%s, %s) to fail", v[0], v[1])
		}
	}
}

func TestURIListValidate(t *testing.T) {
	// V1
	if _, err := ValidateURIList("http://localhost:14000/appauth", "http://localhost:14000/appauth", ""); err != nil {
		t.Errorf("V1: %s", err)
	}

	// V2
	if _, err := ValidateURIList("http://localhost:14000/appauth", "http://localhost:14000/app", ""); err == nil {
		t.Error("V2 should have failed")
	}

	// V3
	if _, err := ValidateURIList("http://xxx:14000/appauth;http://localhost:14000/appauth", "http://localhost:14000/appauth", ";"); err != nil {
		t.Errorf("V3: %s", err)
	}

	// V4
	if _, err := ValidateURIList("http://xxx:14000/appauth;http://localhost:14000/appauth", "http://localhost:14000/app", ";"); err == nil {
		t.Error("V4 should have failed")
	}
}

func TestFirstURI(t *testing.T) {
	assert.Equal(t, "https://auth.mydomain.com/connect", FirstURI("https://auth.mydomain.com/connect mybundle://connect", " "))
	assert.Equal(t, "mybundle://connect", FirstURI("mybundle://connect", " "))
	assert.Equal(t, "mybundle://connect", FirstURI("mybundle://connect", ""))
	assert.Equal(t, "", FirstURI("", " "))
}
