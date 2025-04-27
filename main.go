package main

import (
	"fmt"
	"log"
	"user_service/config"
	"user_service/handlers"
	"user_service/repository"
	"user_service/router"
	"user_service/service"
)

func main() {
	config, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config. Error: %s", err)
	}

	repository, err := repository.NewUserRepository()
	if err != nil {
		log.Fatalf("Failed to create repository. Error: %s", err)
	}

	service, err := service.NewService(repository, config)
	if err != nil {
		log.Fatalf("Failed to create service. Error: %s", err)
	}

	handler := handlers.NewUserHandler(service)

	router, err := router.CreateUserRouter(handler)
	if err != nil {
		log.Fatalf("Failed to create router. Error: %s", err)
	}

	address := fmt.Sprintf("%s:%s", config.Host, config.Port)
	err = router.Run(address)
	if err != nil {
		log.Fatalf("Failed to start router. Error: %s", err)
	}
}
