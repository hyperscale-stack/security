// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorGet(t *testing.T) {
	for _, item := range []struct {
		id       DefaultErrorID
		expedted string
	}{
		{E_ACCESS_DENIED, "The resource owner or authorization server denied the request."},
		{DefaultErrorID("foo"), "foo"},
	} {
		assert.Equal(t, item.expedted, deferror.Get(item.id))
	}
}
