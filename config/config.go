package config

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"user_service/utils"
)

type Config struct {
	Host          string
	Port          string
	SecretKey     []byte
	TokenDuration uint64
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
	tokenDurationString, err := utils.GetEnvVar("TOKEN_DURATION_IN_SECONDS")
	if err != nil {
		return nil, fmt.Errorf("missing environment variable TOKEN_DURATION_IN_SECONDS")
	}
	tokenDuration, err := strconv.ParseUint(tokenDurationString, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to convert TOKEN_DURATION_IN_SECONDS to uint64. Error: %s", err)
	}
	return &Config{Host: host, Port: port, SecretKey: secretKey, TokenDuration: tokenDuration}, nil
}
