// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResponseJSON(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()

	storageMock := &MockStorageProvider{}

	r := NewResponse(storageMock)

	r.Output["access_token"] = "1234"
	r.Output["token_type"] = "5678"

	err = OutputJSON(r, w, req)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Result().Header.Get("Content-Type"))

	// parse output json
	output := make(map[string]interface{})
	err = json.Unmarshal(w.Body.Bytes(), &output)
	assert.NoError(t, err)

	assert.Contains(t, output, "access_token")
	assert.Equal(t, "1234", output["access_token"])

	assert.Contains(t, output, "token_type")
	assert.Equal(t, "5678", output["token_type"])
}

func TestErrorResponseJSON(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()

	storageMock := &MockStorageProvider{}

	r := NewResponse(storageMock)
	r.ErrorStatusCode = 500
	r.SetError(E_INVALID_REQUEST, "")

	err = OutputJSON(r, w, req)
	assert.NoError(t, err)

	assert.Equal(t, 500, w.Code)

	assert.Equal(t, "application/json", w.Result().Header.Get("Content-Type"))

	// parse output json
	output := make(map[string]interface{})
	err = json.Unmarshal(w.Body.Bytes(), &output)
	assert.NoError(t, err)

	assert.Contains(t, output, "error")
	assert.Equal(t, E_INVALID_REQUEST.String(), output["error"])
}

func TestRedirectResponseJSON(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()

	storageMock := &MockStorageProvider{}

	r := NewResponse(storageMock)
	r.SetRedirect("http://localhost:14000")

	err = OutputJSON(r, w, req)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusFound, w.Code)

	assert.Equal(t, "http://localhost:14000", w.Result().Header.Get("Location"))
}

func TestRedirectResponseJSONWithError(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()

	storageMock := &MockStorageProvider{}

	r := NewResponse(storageMock)
	r.SetRedirect(":14000")

	err = OutputJSON(r, w, req)
	assert.EqualError(t, err, "parse url failed: parse \":14000\": missing protocol scheme")

	assert.Equal(t, http.StatusOK, w.Code)

	assert.Equal(t, "", w.Result().Header.Get("Location"))
}
