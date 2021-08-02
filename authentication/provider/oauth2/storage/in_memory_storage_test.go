// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package storage

import (
	"testing"

	"github.com/hyperscale-stack/security/authentication/provider/oauth2"
	"github.com/stretchr/testify/assert"
)

func TestInMemoryStorage(t *testing.T) {
	s := NewInMemoryStorage()

	client := &oauth2.DefaultClient{
		ID:          "5cc06c3b-5755-4229-958c-a515a245aaeb",
		Secret:      "WTvuAztPD2XBauomleRzGFYuZawS07Ym",
		RedirectURI: "https://connect.myservice.tld",
	}

	// Client
	client2, err := s.LoadClient(client.ID)
	assert.EqualError(t, err, oauth2.ErrClientNotFound.Error())
	assert.Nil(t, client2)

	err = s.SaveClient(client)
	assert.NoError(t, err)

	client2, err = s.LoadClient(client.ID)
	assert.NoError(t, err)
	assert.Same(t, client, client2)

	err = s.RemoveClient(client.ID)
	assert.NoError(t, err)

	client2, err = s.LoadClient(client.ID)
	assert.EqualError(t, err, oauth2.ErrClientNotFound.Error())
	assert.Nil(t, client2)

	// Access Token
	access := &oauth2.AccessInfo{
		AccessToken: "OKjQ0VjYmJxP8N0TzXH5lxvIOZj4bCM0DlsCvuiL96HCQEhJ8A9ozY8jJ5Ep38vaVvn082fgApThX7NZ7pktKn57A667kEeWLPW0KVA3x1flYdBvkIvHOAZYyvUeKK9q",
	}

	access2, err := s.LoadAccess(access.AccessToken)
	assert.EqualError(t, err, oauth2.ErrAccessNotFound.Error())
	assert.Nil(t, access2)

	err = s.SaveAccess(access)
	assert.NoError(t, err)

	access2, err = s.LoadAccess(access.AccessToken)
	assert.NoError(t, err)
	assert.Same(t, access, access2)

	err = s.RemoveAccess(access.AccessToken)
	assert.NoError(t, err)

	access2, err = s.LoadAccess(access.AccessToken)
	assert.EqualError(t, err, oauth2.ErrAccessNotFound.Error())
	assert.Nil(t, access2)

	// Refresh Token
	access = &oauth2.AccessInfo{
		RefreshToken: "2oQDkOWnbqtJoEs24MkVEB4WNJnqyoAIErvSJRhjg562K8GznWLbLZuStQodKvReSedAqufswaSZduhlgOuCNcQj9aGbCKPAnXUVvmX7Vmgvryp9PaZVbuqj0HfzN9tD",
	}

	access2, err = s.LoadRefresh(access.RefreshToken)
	assert.EqualError(t, err, oauth2.ErrRefreshNotFound.Error())
	assert.Nil(t, access2)

	err = s.SaveRefresh(access)
	assert.NoError(t, err)

	access2, err = s.LoadRefresh(access.RefreshToken)
	assert.NoError(t, err)
	assert.Same(t, access, access2)

	err = s.RemoveRefresh(access.RefreshToken)
	assert.NoError(t, err)

	access2, err = s.LoadRefresh(access.RefreshToken)
	assert.EqualError(t, err, oauth2.ErrRefreshNotFound.Error())
	assert.Nil(t, access2)

	// Authorize Code
	authorize := &oauth2.AuthorizeInfo{
		Code: "Je4dJ5RFPRJwuSmuitSo8tX7s3uFOP84sEufxjdqJhiiPABdbxeGofGvvX7LBdvy2ZrwDZy3a6cOF8vgquUlr8yAvA9VpDz4Kv2bZxm0WEl4y3SJSvYPnwBOxRHI5pxK",
	}

	authorize2, err := s.LoadAuthorize(authorize.Code)
	assert.EqualError(t, err, oauth2.ErrAuthorizeNotFound.Error())
	assert.Nil(t, authorize2)

	err = s.SaveAuthorize(authorize)
	assert.NoError(t, err)

	authorize2, err = s.LoadAuthorize(authorize.Code)
	assert.NoError(t, err)
	assert.Same(t, authorize, authorize2)

	err = s.RemoveAuthorize(authorize.Code)
	assert.NoError(t, err)

	authorize2, err = s.LoadAuthorize(authorize.Code)
	assert.EqualError(t, err, oauth2.ErrAuthorizeNotFound.Error())
	assert.Nil(t, authorize2)
}
