// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultClient(t *testing.T) {
	dc := &DefaultClient{
		ID:          "01c1c799-81a8-4bd0-9998-c6abae3cc473",
		Secret:      "MfpCIRnFcwA5GiKPtAMZdXb2ayehhEj9",
		RedirectURI: "https://connect.myservice.tld/",
		UserData:    "foo",
	}

	assert.Equal(t, "01c1c799-81a8-4bd0-9998-c6abae3cc473", dc.GetID())
	assert.Equal(t, "MfpCIRnFcwA5GiKPtAMZdXb2ayehhEj9", dc.GetSecret())
	assert.Equal(t, "https://connect.myservice.tld/", dc.GetRedirectURI())
	assert.Equal(t, "foo", dc.GetUserData())
	assert.True(t, dc.ClientSecretMatches("MfpCIRnFcwA5GiKPtAMZdXb2ayehhEj9"))

	dc1 := &DefaultClient{}

	dc1.CopyFrom(dc)

	assert.Equal(t, dc.GetID(), dc1.GetID())
	assert.Equal(t, dc.GetSecret(), dc1.GetSecret())
	assert.Equal(t, dc.GetRedirectURI(), dc1.GetRedirectURI())
	assert.Equal(t, dc.GetUserData(), dc1.GetUserData())
	assert.True(t, dc1.ClientSecretMatches(dc.GetSecret()))

}
