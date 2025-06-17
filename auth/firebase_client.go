package auth

import (
	"context"

	firebaseAuth "firebase.google.com/go/v4/auth"
)

type FirebaseClient interface {
	VerifyIDToken(ctx context.Context, idToken string) (*firebaseAuth.Token, error)
}

type MockFirebaseClient struct{}

var _ FirebaseClient = (*MockFirebaseClient)(nil)

func (c *MockFirebaseClient) VerifyIDToken(ctx context.Context, idToken string) (*firebaseAuth.Token, error) {
	claims := make(map[string]interface{})
	claims["email"] = idToken
	return &firebaseAuth.Token{
		Claims: claims,
	}, nil
}
