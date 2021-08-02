package main

import "github.com/hyperscale-stack/security/authentication/provider/oauth2"

type OAuth2Storage struct {
}

func NewOAuth2Storage() *OAuth2Storage {
	return &OAuth2Storage{}
}

var _ oauth2.Storage = (*OAuth2Storage)(nil)

func (s *OAuth2Storage) SaveClient(oauth2.Client) error {
	return nil
}

func (s *OAuth2Storage) LoadClient(id string) (oauth2.Client, error) {
	return nil, nil
}

func (s *OAuth2Storage) RemoveClient(id string) error {
	return nil
}

func (s *OAuth2Storage) SaveAccess(*oauth2.AccessInfo) error {
	return nil
}

func (s *OAuth2Storage) LoadAccess(token string) (*oauth2.AccessInfo, error) {
	return nil, nil
}

func (s *OAuth2Storage) RemoveAccess(token string) error {
	return nil
}

func (s *OAuth2Storage) SaveRefresh(*oauth2.AccessInfo) error {
	return nil
}

func (s *OAuth2Storage) LoadRefresh(token string) (*oauth2.AccessInfo, error) {
	return nil, nil
}

func (s *OAuth2Storage) RemoveRefresh(token string) error {
	return nil
}

func (s *OAuth2Storage) SaveAuthorize(*oauth2.AuthorizeInfo) error {
	return nil
}

func (s *OAuth2Storage) LoadAuthorize(code string) (*oauth2.AuthorizeInfo, error) {
	return nil, nil
}

func (s *OAuth2Storage) RemoveAuthorize(code string) error {
	return nil
}
