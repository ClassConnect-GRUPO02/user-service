package auth

import (
	"context"
	"fmt"

	idtoken "google.golang.org/api/idtoken"
)

type IdTokenValidator interface {
	ValidateIdToken(ctx context.Context, idToken, audience string) (string, error)
}

type MockIdTokenValidator struct{}

var _ IdTokenValidator = (*MockIdTokenValidator)(nil)

func (v *MockIdTokenValidator) ValidateIdToken(ctx context.Context, idToken, audience string) (string, error) {
	email := idToken
	return email, nil
}

type GoogleIdTokenValidator struct{}

func (v *GoogleIdTokenValidator) ValidateIdToken(ctx context.Context, idToken, audience string) (string, error) {
	payload, err := idtoken.Validate(ctx, idToken, audience)
	if err != nil {
		return "", err
	}
	tokenEmail, ok := payload.Claims["email"]
	if !ok {
		return "", fmt.Errorf("missing email on idToken")
	}
	email := fmt.Sprint(tokenEmail)
	return email, nil
}
