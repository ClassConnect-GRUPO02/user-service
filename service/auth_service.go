package service

import (
	"time"
	"user_service/auth"
	"user_service/models"
)

// TODO: extract this to an env var or config value.
const TOKEN_DURATION_IN_SECONDS = 10

func (s *Service) ValidateToken(token string) error {
	tokenClaims, err := auth.ValidateToken(token)
	if err != nil {
		return models.InvalidToken()
	}

	if tokenHasExpired(tokenClaims.IssuedAt) {
		return models.SessionExpired()
	}

	return nil
}

func tokenHasExpired(issuedAtTimestamp uint64) bool {
	now := time.Now().Unix()
	tokenExpirationTimestamp := int64(issuedAtTimestamp) + TOKEN_DURATION_IN_SECONDS
	return now >= tokenExpirationTimestamp
}
