// Code generated by mockery v2.53.3. DO NOT EDIT.

package mocks

import (
	models "user_service/models"

	mock "github.com/stretchr/testify/mock"
)

// Repository is an autogenerated mock type for the Repository type
type Repository struct {
	mock.Mock
}

// AddUser provides a mock function with given fields: user
func (_m *Repository) AddUser(user models.User) error {
	ret := _m.Called(user)

	if len(ret) == 0 {
		panic("no return value specified for AddUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(models.User) error); ok {
		r0 = rf(user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IsEmailRegistered provides a mock function with given fields: email
func (_m *Repository) IsEmailRegistered(email string) (bool, error) {
	ret := _m.Called(email)

	if len(ret) == 0 {
		panic("no return value specified for IsEmailRegistered")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (bool, error)); ok {
		return rf(email)
	}
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(email)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewRepository creates a new instance of Repository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *Repository {
	mock := &Repository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
