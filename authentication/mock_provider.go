// Code generated by mockery v0.0.0-dev. DO NOT EDIT.

package authentication

import (
	http "net/http"

	credential "github.com/hyperscale-stack/security/authentication/credential"

	mock "github.com/stretchr/testify/mock"
)

// MockProvider is an autogenerated mock type for the Provider type
type MockProvider struct {
	mock.Mock
}

// Authenticate provides a mock function with given fields: r, creds
func (_m *MockProvider) Authenticate(r *http.Request, creds credential.Credential) (*http.Request, error) {
	ret := _m.Called(r, creds)

	var r0 *http.Request
	if rf, ok := ret.Get(0).(func(*http.Request, credential.Credential) *http.Request); ok {
		r0 = rf(r, creds)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*http.Request)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*http.Request, credential.Credential) error); ok {
		r1 = rf(r, creds)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IsSupported provides a mock function with given fields: creds
func (_m *MockProvider) IsSupported(creds credential.Credential) bool {
	ret := _m.Called(creds)

	var r0 bool
	if rf, ok := ret.Get(0).(func(credential.Credential) bool); ok {
		r0 = rf(creds)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}
