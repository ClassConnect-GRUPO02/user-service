package models

import (
	"fmt"
	"net/http"
)

type Error struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail"`
	Instance string `json:"instance"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s (status=%d)", e.Title, e.Detail, e.Status)
}

func EmailAlreadyRegisteredError(email string) error {
	detail := fmt.Sprintf("The email address '%s' is already associated with an existing account.", email)
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "Email already registered",
		Status:   http.StatusConflict,
		Detail:   detail,
		Instance: "/users",
	}
}

func InternalServerError() error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "Internal server error",
		Status:   http.StatusInternalServerError,
		Detail:   "Internal server error",
		Instance: "/users",
	}
}
