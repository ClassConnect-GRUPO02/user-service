include .env

server_image: 
	docker build . -f Dockerfile -t server

test_image:
	docker build . -f Dockerfile.test -t test

start_server:
	docker run --rm -it \
		--name server \
		-e HOST=$(HOST) \
		-e PORT=$(PORT) \
		-e ENVIRONMENT=$(ENVIRONMENT) \
		-p $(PORT):$(PORT) server

tests:
	docker compose up --abort-on-container-exit
	docker compose down
