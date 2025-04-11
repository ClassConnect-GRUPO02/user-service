package service

import (
	"time"
	"user_service/auth"
	"user_service/models"
)

func (s *Service) ValidateToken(token string) error {
	tokenClaims, err := auth.ValidateToken(token, s.secretKey)
	if err != nil {
		return models.InvalidToken()
	}

	if s.TokenHasExpired(tokenClaims.IssuedAt) {
		return models.SessionExpired()
	}

	return nil
}

func (s *Service) TokenHasExpired(issuedAtTimestamp uint64) bool {
	now := time.Now().Unix()
	tokenExpirationTimestamp := int64(issuedAtTimestamp) + int64(s.tokenDuration)
	return now >= tokenExpirationTimestamp
}
