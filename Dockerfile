FROM golang:1.23 as golang

WORKDIR /usr/src/app

COPY service/ .
RUN go mod download

RUN go build -v -o /usr/local/bin/app ./...

FROM ubuntu:22.04
COPY --from=golang /usr/local/bin/app /usr/local/bin/app

CMD ["app"]
