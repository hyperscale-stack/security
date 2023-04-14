// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

var (
	ErrNotARedirectResponse = errors.New("not a redirect response")
)

// Data for response output.
type ResponseData map[string]interface{}

// Response type enum.
type ResponseType int

const (
	DATA ResponseType = iota
	REDIRECT
)

// Server response.
type Response struct {
	Type               ResponseType
	StatusCode         int
	StatusText         string
	ErrorStatusCode    int
	URL                string
	Output             ResponseData
	Headers            http.Header
	IsError            bool
	ErrorID            DefaultErrorID
	InternalError      error
	RedirectInFragment bool

	// Storage to use in this response - required
	Storage StorageProvider
}

func NewResponse(storage StorageProvider) *Response {
	r := &Response{
		Type:            DATA,
		StatusCode:      200,
		ErrorStatusCode: 200,
		Output:          make(ResponseData),
		Headers:         make(http.Header),
		IsError:         false,
		Storage:         storage, // Clone ?
	}
	r.Headers.Add(
		"Cache-Control",
		"no-cache, no-store, max-age=0, must-revalidate",
	)
	r.Headers.Add("Pragma", "no-cache")
	r.Headers.Add("Expires", "Fri, 01 Jan 1990 00:00:00 GMT")

	return r
}

// SetError sets an error id and description on the Response
// state and uri are left blank.
func (r *Response) SetError(id DefaultErrorID, description string) {
	r.SetErrorURI(id, description, "", "")
}

// SetErrorState sets an error id, description, and state on the Response
// uri is left blank.
func (r *Response) SetErrorState(id DefaultErrorID, description string, state string) {
	r.SetErrorURI(id, description, "", state)
}

// SetErrorURI sets an error id, description, state, and uri on the Response.
func (r *Response) SetErrorURI(id DefaultErrorID, description string, uri string, state string) {
	// get default error message
	if description == "" {
		description = deferror.Get(id)
	}

	// set error parameters
	r.IsError = true
	r.ErrorID = id
	r.StatusCode = r.ErrorStatusCode

	if r.StatusCode != http.StatusOK {
		r.StatusText = description
	} else {
		r.StatusText = ""
	}

	r.Output = make(ResponseData) // clear output
	r.Output["error"] = id
	r.Output["error_description"] = description

	if uri != "" {
		r.Output["error_uri"] = uri
	}

	if state != "" {
		r.Output["state"] = state
	}
}

// SetRedirect changes the response to redirect to the given url.
func (r *Response) SetRedirect(url string) {
	// set redirect parameters
	r.Type = REDIRECT
	r.URL = url
}

// SetRedirectFragment sets redirect values to be passed in fragment instead of as query parameters.
func (r *Response) SetRedirectFragment(f bool) {
	r.RedirectInFragment = f
}

// GetRedirectURL returns the redirect url with all query string parameters.
func (r *Response) GetRedirectURL() (string, error) {
	if r.Type != REDIRECT {
		return "", ErrNotARedirectResponse
	}

	u, err := url.Parse(r.URL)
	if err != nil {
		return "", fmt.Errorf("parse url failed: %w", err)
	}

	var q url.Values
	if r.RedirectInFragment {
		// start with empty set for fragment
		q = url.Values{}
	} else {
		// add parameters to existing query
		q = u.Query()
	}

	// add parameters
	for n, v := range r.Output {
		q.Set(n, fmt.Sprint(v))
	}

	// https://tools.ietf.org/html/rfc6749#section-4.2.2
	// Fragment should be encoded as application/x-www-form-urlencoded (%-escaped, spaces are represented as '+')
	// The stdlib URL#String() doesn't make that easy to accomplish, so build this ourselves
	if r.RedirectInFragment {
		u.Fragment = ""
		redirectURI := u.String() + "#" + q.Encode()

		return redirectURI, nil
	}

	// Otherwise, update the query and encode normally
	u.RawQuery = q.Encode()
	u.Fragment = ""

	return u.String(), nil
}
