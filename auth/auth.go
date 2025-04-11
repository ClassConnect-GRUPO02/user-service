package auth

import (
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
)

type CustomClaims struct {
	IssuedAt uint64 `json:"iat"`
	jwt.StandardClaims
}

// TODO: read this from env var
var secretKey = string("76028c74d31446243846ab36cbb51ddc26e82cfc7f7847258fd599927d786110075090d3a2275528beaa8510b14538525bd8c13cd154e6ba75ee582fd0823ef8d2e48000a173d6bb35e9513650020d0ed0a5851f8e08be63f87b5f3811ff85c4116d3ded4becbdef76d680e9aa9a78ea1205951aacf758ab7fc8dbf52a1494fe786f439560ad6882c82a1de743147c5c7b82d8102d69d4b378978a0e1dc14b34bbe6b77a48a4c5bd2cafed3ecfef922566609dc26b2467e5439a4f6b25368981d3275b639f3e00730c5da604345369160a7d1cfce212a640beae8c11ce8cf268b565194ce7dd5ae24cd825fa4a9d91b3825531d7cdbfad074ef1c676a17fc062")

func IssueToken() (string, error) {
	claims := jwt.MapClaims{
		// Issued at (the unix timestamp at which the token was issued)
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	key, err := hex.DecodeString(secretKey)
	if err != nil {
		return "", err
	}
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// ValidateToken validates the given token, returning an error when the token is invalid.
// If the token is valid, it returns the token claims.
func ValidateToken(tokenString string) (*CustomClaims, error) {
	customClaims := CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &customClaims, func(t *jwt.Token) (interface{}, error) {
		return hex.DecodeString(secretKey)
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
