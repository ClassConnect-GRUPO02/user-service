package config

import (
	"encoding/hex"
	"fmt"
	"user_service/utils"
)

type Config struct {
	Host               string
	Port               string
	SecretKey          []byte
	TokenDuration      uint64
	BlockingTimeWindow int64
	BlockingDuration   int64
	LoginAttemptsLimit int64
	Email              string
	EmailPassword      string
}

func LoadConfig() (*Config, error) {
	host, err := utils.GetEnvVar("HOST")
	if err != nil {
		return nil, fmt.Errorf("missing environment variable HOST")
	}
	port, err := utils.GetEnvVar("PORT")
	if err != nil {
		return nil, fmt.Errorf("missing environment variable PORT")
	}
	secretKeyString, err := utils.GetEnvVar("SECRET_KEY")
	if err != nil {
		return nil, fmt.Errorf("missing environment variable SECRET_KEY")
	}
	secretKey, err := hex.DecodeString(secretKeyString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret key")
	}
	tokenDuration, err := utils.GetIntEnvVar("TOKEN_DURATION_IN_SECONDS")
	if err != nil {
		return nil, err
	}
	blockingTimeWindow, err := utils.GetIntEnvVar("BLOCKING_TIME_WINDOW_IN_SECONDS")
	if err != nil {
		return nil, err
	}
	blockingDuration, err := utils.GetIntEnvVar("BLOCKING_DURATION_IN_SECONDS")
	if err != nil {
		return nil, err
	}
	loginAttemptsLimit, err := utils.GetIntEnvVar("LOGIN_ATTEMPTS_LIMIT")
	if err != nil {
		return nil, err
	}
	email, err := utils.GetEnvVar("EMAIL")
	if err != nil {
		return nil, fmt.Errorf("missing environment variable EMAIL")
	}
	emailPassword, err := utils.GetEnvVar("EMAIL_PASSWORD")
	if err != nil {
		return nil, fmt.Errorf("missing environment variable EMAIL_PASSWORD")
	}

	return &Config{
		Host:               host,
		Port:               port,
		SecretKey:          secretKey,
		TokenDuration:      uint64(tokenDuration),
		BlockingTimeWindow: blockingTimeWindow,
		BlockingDuration:   blockingDuration,
		LoginAttemptsLimit: loginAttemptsLimit,
		Email:              email,
		EmailPassword:      emailPassword,
	}, nil
}
