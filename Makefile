include .env

service_image: 
	docker build . -f Dockerfile -t user_service

test_image:
	docker build . -f Dockerfile.test -t test

start_service:
	docker run --rm -it \
		--name user_service \
		-e HOST=$(HOST) \
		-e PORT=$(PORT) \
		-e ENVIRONMENT=$(ENVIRONMENT) \
		-p $(PORT):$(PORT) user_service

tests:
	docker compose up --abort-on-container-exit
	docker compose down
