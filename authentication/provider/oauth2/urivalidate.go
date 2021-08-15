// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	ErrNoBlank = errors.New("urls cannot be blank")
)

// error returned when validation don't match.
type URIValidationError string

func (e URIValidationError) Error() string {
	return string(e)
}

func newURIValidationError(msg string, base string, redirect string) URIValidationError {
	return URIValidationError(fmt.Sprintf("%s: %s / %s", msg, base, redirect))
}

// ParseURLs resolving uri references to base url.
func ParseURLs(baseUrl, redirectUrl string) (retBaseUrl, retRedirectUrl *url.URL, err error) {
	var base, redirect *url.URL
	// parse base url
	if base, err = url.Parse(baseUrl); err != nil {
		return nil, nil, fmt.Errorf("parse base url failed: %w", err)
	}

	// parse redirect url
	if redirect, err = url.Parse(redirectUrl); err != nil {
		return nil, nil, fmt.Errorf("parse redirect url failed: %w", err)
	}

	// must not have fragment
	if base.Fragment != "" || redirect.Fragment != "" {
		return nil, nil, newURIValidationError("url must not include fragment.", baseUrl, redirectUrl)
	}

	// Scheme must match
	if redirect.Scheme != base.Scheme {
		return nil, nil, newURIValidationError("scheme mismatch", baseUrl, redirectUrl)
	}

	// Host must match
	if redirect.Host != base.Host {
		return nil, nil, newURIValidationError("host mismatch", baseUrl, redirectUrl)
	}

	// resolve references to base url
	retBaseUrl = (&url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/"}).ResolveReference(&url.URL{Path: base.Path})
	retRedirectUrl = (&url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/"}).ResolveReference(&url.URL{Path: redirect.Path, RawQuery: redirect.RawQuery})

	return
}

// ValidateUriList validates that redirectUri is contained in baseUriList.
// baseUriList may be a string separated by separator.
// If separator is blank, validate only 1 URI.
func ValidateURIList(baseUriList string, redirectUri string, separator string) (realRedirectUri string, err error) {
	// make a list of uris
	var slist []string
	if separator != "" {
		slist = strings.Split(baseUriList, separator)
	} else {
		slist = make([]string, 0)
		slist = append(slist, baseUriList)
	}

	for _, sitem := range slist {
		realRedirectUri, err = ValidateURI(sitem, redirectUri)
		// validated, return no error
		if err == nil {
			return realRedirectUri, nil
		}

		// if there was an error that is not a validation error, return it
		//nolint:errorlint
		if _, iok := err.(URIValidationError); !iok {
			return "", err
		}
	}

	return "", newURIValidationError("urls don't validate", baseUriList, redirectUri)
}

// ValidateURI validates that redirectUri is contained in baseUri.
func ValidateURI(baseUri string, redirectUri string) (realRedirectUri string, err error) {
	if baseUri == "" || redirectUri == "" {
		return "", ErrNoBlank
	}

	base, redirect, err := ParseURLs(baseUri, redirectUri)
	if err != nil {
		return "", err
	}

	// allow exact path matches
	if base.Path == redirect.Path {
		return redirect.String(), nil
	}

	// ensure prefix matches are actually subpaths
	requiredPrefix := strings.TrimRight(base.Path, "/") + "/"
	if !strings.HasPrefix(redirect.Path, requiredPrefix) {
		return "", newURIValidationError("path prefix doesn't match", baseUri, redirectUri)
	}

	return redirect.String(), nil
}

// FirstURI returns the first uri from an uri list.
func FirstURI(baseUriList string, separator string) string {
	if separator == "" {
		return baseUriList
	}

	return strings.Split(baseUriList, separator)[0]
}
