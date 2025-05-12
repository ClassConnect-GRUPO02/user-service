include .env

service_image: 
	docker build . -f Dockerfile -t user_service

start:
	$(MAKE) service_image
	docker compose up --force-recreate -V --abort-on-container-exit
	docker compose down

test:
	docker compose -f docker-compose-test.yaml up --abort-on-container-exit --build
	docker compose down -v
