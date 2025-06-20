package service

import (
	"time"
	"user_service/auth"
	"user_service/models"
)

func (s *Service) ValidateToken(token string) (*auth.CustomClaims, error) {
	tokenClaims, err := s.authService.ValidateToken(token)
	if err != nil {
		return nil, models.InvalidToken()
	}

	if s.TokenHasExpired(tokenClaims.IssuedAt) {
		return nil, models.SessionExpired()
	}

	return tokenClaims, nil
}

func (s *Service) TokenHasExpired(issuedAtTimestamp uint64) bool {
	now := time.Now().Unix()
	tokenExpirationTimestamp := int64(issuedAtTimestamp) + int64(s.tokenDuration)
	return now >= tokenExpirationTimestamp
}

func (s *Service) RefreshTokenHasExpired(issuedAtTimestamp uint64) bool {
	now := time.Now().Unix()
	tokenExpirationTimestamp := int64(issuedAtTimestamp) + int64(s.refreshTokenDuration)
	return now >= tokenExpirationTimestamp
}

func (s *Service) ResetPasswordTokenHasExpired(issuedAtTimestamp uint64) bool {
	now := time.Now().Unix()
	tokenExpirationTimestamp := int64(issuedAtTimestamp) + int64(s.resetPasswordTokenDuration)
	return now >= tokenExpirationTimestamp
}

func (s *Service) GetUserIdFromToken(token string) (string, error) {
	tokenClaims, err := s.authService.ValidateToken(token)
	if err != nil {
		return "", models.InvalidToken()
	}
	return tokenClaims.Id, nil
}

func (s *Service) ValidateRefreshToken(token string) (*auth.RefreshClaims, error) {
	tokenClaims, err := s.authService.ValidateRefreshToken(token)
	if err != nil {
		return nil, models.InvalidToken()
	}

	if tokenClaims.Type != "refresh" {
		return nil, models.InvalidToken()
	}

	if s.RefreshTokenHasExpired(tokenClaims.IssuedAt) {
		return nil, models.SessionExpired()
	}

	return tokenClaims, nil
}
