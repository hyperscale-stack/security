// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"net/http"
)

// OutputJSON encodes the Response to JSON and writes to the http.ResponseWriter.
func OutputJSON(rs *Response, w http.ResponseWriter, r *http.Request) error {
	// Add headers
	for i, k := range rs.Headers {
		for _, v := range k {
			w.Header().Add(i, v)
		}
	}

	if rs.Type == REDIRECT {
		// Output redirect with parameters
		u, err := rs.GetRedirectURL()
		if err != nil {
			return err
		}

		w.Header().Add("Location", u)
		w.WriteHeader(302)

		return nil
	}

	// set content type if the response doesn't already have one associated with it
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}

	w.WriteHeader(rs.StatusCode)

	//nolint:wrapcheck
	return json.NewEncoder(w).Encode(rs.Output)
}
