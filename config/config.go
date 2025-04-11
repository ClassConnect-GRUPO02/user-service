package config

import (
	"encoding/hex"
	"fmt"
	"user_service/utils"
)

type Config struct {
	Host      string
	Port      string
	SecretKey []byte
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

	return &Config{Host: host, Port: port, SecretKey: secretKey}, nil
}
