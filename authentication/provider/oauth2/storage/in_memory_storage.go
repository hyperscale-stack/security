// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package storage

import (
	"sync"

	"github.com/hyperscale-stack/security/authentication/provider/oauth2"
)

var _ oauth2.Storage = (*InMemoryStorage)(nil)

type InMemoryStorage struct {
	clients    sync.Map
	accesses   sync.Map
	refreshs   sync.Map
	authorizes sync.Map
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{}
}

func (s *InMemoryStorage) SaveClient(client oauth2.Client) error {
	s.clients.Store(client.GetID(), client)

	return nil
}

func (s *InMemoryStorage) LoadClient(id string) (oauth2.Client, error) {
	if client, ok := s.clients.Load(id); ok {
		return client.(oauth2.Client), nil
	}

	return nil, oauth2.ErrClientNotFound
}

func (s *InMemoryStorage) RemoveClient(id string) error {
	s.clients.Delete(id)

	return nil
}

func (s *InMemoryStorage) SaveAccess(access *oauth2.AccessInfo) error {
	s.accesses.Store(access.AccessToken, access)

	return nil
}

func (s *InMemoryStorage) LoadAccess(token string) (*oauth2.AccessInfo, error) {
	if access, ok := s.accesses.Load(token); ok {
		return access.(*oauth2.AccessInfo), nil
	}

	return nil, oauth2.ErrAccessNotFound
}

func (s *InMemoryStorage) RemoveAccess(token string) error {
	s.accesses.Delete(token)

	return nil
}

func (s *InMemoryStorage) SaveRefresh(access *oauth2.AccessInfo) error {
	s.refreshs.Store(access.RefreshToken, access)

	return nil
}

func (s *InMemoryStorage) LoadRefresh(token string) (*oauth2.AccessInfo, error) {
	if access, ok := s.refreshs.Load(token); ok {
		return access.(*oauth2.AccessInfo), nil
	}

	return nil, oauth2.ErrRefreshNotFound
}

func (s *InMemoryStorage) RemoveRefresh(token string) error {
	s.refreshs.Delete(token)

	return nil
}

func (s *InMemoryStorage) SaveAuthorize(authorize *oauth2.AuthorizeInfo) error {
	s.authorizes.Store(authorize.Code, authorize)

	return nil
}

func (s *InMemoryStorage) LoadAuthorize(code string) (*oauth2.AuthorizeInfo, error) {
	if authorize, ok := s.authorizes.Load(code); ok {
		return authorize.(*oauth2.AuthorizeInfo), nil
	}

	return nil, oauth2.ErrAuthorizeNotFound
}

func (s *InMemoryStorage) RemoveAuthorize(code string) error {
	s.authorizes.Delete(code)

	return nil
}
