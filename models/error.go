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

func EmailNotVerifiedError(email string) error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "Email not verified",
		Status:   http.StatusUnauthorized,
		Detail:   fmt.Sprintf("User cannot login because the email %s is not verified", email),
		Instance: "/login",
	}
}

func InvalidCredentialsError() error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "Invalid credentials error",
		Status:   http.StatusUnauthorized,
		Detail:   "Could not authenticate the user (invalid email or password)",
		Instance: "/login",
	}
}

func UserBlockedError() error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "The account is blocked",
		Status:   http.StatusForbidden,
		Detail:   "The given account is currently blocked and is not authorized to log in.",
		Instance: "/login",
	}
}

func InvalidToken() error {
	return &Error{
		Type:   "about:blank", // TODO: consider setting the right type here
		Title:  "Invalid token",
		Status: http.StatusUnauthorized,
		Detail: "The given JWT token is invalid",
	}
}

func SessionExpired() error {
	return &Error{
		Type:   "about:blank", // TODO: consider setting the right type here
		Title:  "Session expired",
		Status: http.StatusUnauthorized,
		Detail: "The current session has expired.",
	}
}

func UserNotFoundError(id string) error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "User not found",
		Status:   http.StatusNotFound,
		Detail:   fmt.Sprintf("The user with id %s was not found", id),
		Instance: fmt.Sprintf("/user/%s", id),
	}
}

func InvalidExpoToken(userId int64, expoToken string) error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "Invalid expo token",
		Status:   http.StatusUnauthorized,
		Detail:   fmt.Sprintf("The expo token '%s' is invalid", expoToken),
		Instance: fmt.Sprintf("/users/%d/push-token", userId),
	}
}

func MissingExpoPushToken(id string, instance string) error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "Missing expo push token",
		Status:   http.StatusNotFound,
		Detail:   fmt.Sprintf("The user %s is missing an Expo push token", id),
		Instance: instance,
	}
}

func BadRequestInvalidId(id, instance string) error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "Bad Request",
		Status:   http.StatusBadRequest,
		Detail:   fmt.Sprintf("Invalid id: %s", id),
		Instance: instance,
	}
}

func BadRequestMissingFields(instance string) error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "Bad Request",
		Status:   http.StatusBadRequest,
		Detail:   "The request is missing fields",
		Instance: instance,
	}
}

func BadRequestInvalidNotificationType(notificationType, instance string) error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "Bad Request",
		Status:   http.StatusBadRequest,
		Detail:   fmt.Sprintf("Invalid notification type: %s", notificationType),
		Instance: instance,
	}
}

func InvalidPinError(pin int, instance string) error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "Invalid PIN",
		Status:   http.StatusUnauthorized,
		Detail:   fmt.Sprintf("The verification PIN %d is invalid", pin),
		Instance: instance,
	}
}

func ExpiredPinError(pin int, instance string) error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "Expired PIN",
		Status:   http.StatusUnauthorized,
		Detail:   fmt.Sprintf("The verification PIN %d has already expired", pin),
		Instance: instance,
	}
}

func ExpiredTokenError(instance string) error {
	return &Error{
		Type:     "about:blank", // TODO: consider setting the right type here
		Title:    "Expired JWT Token",
		Status:   http.StatusUnauthorized,
		Detail:   "The JWT token has expired",
		Instance: instance,
	}
}
