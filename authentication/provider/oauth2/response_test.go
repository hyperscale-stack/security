// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResponseGetRedirectURLWithDataRequest(t *testing.T) {
	storageMock := &MockStorageProvider{}

	r := NewResponse(storageMock)

	r.Type = DATA

	url, err := r.GetRedirectURL()
	assert.EqualError(t, err, ErrNotARedirectResponse.Error())

	assert.Equal(t, "", url)
}

func TestResponseGetRedirectURLWithRedirectInFragment(t *testing.T) {
	storageMock := &MockStorageProvider{}

	r := NewResponse(storageMock)

	r.Output["foo"] = "bar"
	r.SetRedirect("https://oauth.mydomain.tld/connect")
	r.SetRedirectFragment(true)

	url, err := r.GetRedirectURL()
	assert.NoError(t, err)

	assert.Equal(t, "https://oauth.mydomain.tld/connect#foo=bar", url)
}

func TestResponseSetErrorURI(t *testing.T) {
	storageMock := &MockStorageProvider{}

	r := NewResponse(storageMock)

	r.SetErrorURI(E_ACCESS_DENIED, "access denied", "https://oauth.mydomain.tld/connect", "foobar")

	assert.True(t, r.IsError)
	assert.Equal(t, http.StatusOK, r.ErrorStatusCode)
	assert.Equal(t, E_ACCESS_DENIED, r.ErrorID)

	assert.Equal(t, "", r.StatusText)

	assert.Contains(t, r.Output, "error_uri")
	assert.Equal(t, "https://oauth.mydomain.tld/connect", r.Output["error_uri"])

	assert.Contains(t, r.Output, "state")
	assert.Equal(t, "foobar", r.Output["state"])

	assert.Contains(t, r.Output, "error")
	assert.Equal(t, E_ACCESS_DENIED, r.Output["error"])

	assert.Contains(t, r.Output, "error_description")
	assert.Equal(t, "access denied", r.Output["error_description"])

}

func TestResponseSetErrorState(t *testing.T) {
	storageMock := &MockStorageProvider{}

	r := NewResponse(storageMock)

	r.SetErrorState(E_ACCESS_DENIED, "", "foobar")

	assert.Contains(t, r.Output, "error")
	assert.Equal(t, E_ACCESS_DENIED, r.Output["error"])

	assert.Contains(t, r.Output, "error_description")
	assert.Equal(t, "The resource owner or authorization server denied the request.", r.Output["error_description"])

	assert.Contains(t, r.Output, "state")
	assert.Equal(t, "foobar", r.Output["state"])
}
