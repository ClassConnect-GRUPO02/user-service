package auth

import (
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
)

type CustomClaims struct {
	IssuedAt uint64 `json:"iat" binding:"required"`
	Id       string `json:"id" binding:"required"`
	jwt.StandardClaims
}

type Auth struct {
	SecretKey []byte
}

func (auth *Auth) IssueToken(id string) (string, error) {
	claims := jwt.MapClaims{
		// Issued at (the unix timestamp at which the token was issued)
		"iat": time.Now().Unix(),
		"id":  id,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(auth.SecretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// ValidateToken validates the given token, returning an error when the token is invalid.
// If the token is valid, it returns the token claims.
func (auth *Auth) ValidateToken(tokenString string) (*CustomClaims, error) {
	customClaims := CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &customClaims, func(t *jwt.Token) (interface{}, error) {
		return auth.SecretKey, nil
	})
	if err != nil {
		log.Printf("Failed to parse token. Error: %s", err)
		return nil, err
	}
	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("failed to decode token claims")
	}

	return claims, nil
}
