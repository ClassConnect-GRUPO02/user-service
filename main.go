package main

import (
	"fmt"
	"log"
	"user_service/config"
	"user_service/router"
)

func main() {
	config, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config. Error: %s", err)
	}

	router, err := router.CreateUserRouter(config)
	if err != nil {
		log.Fatalf("Failed to create router. Error: %s", err)
	}
	address := fmt.Sprintf("%s:%s", config.Host, config.Port)
	err = router.Run(address)
	if err != nil {
		log.Fatalf("Failed to start router. Error: %s", err)
	}
}
