FROM golang:1.23 as golang

WORKDIR /usr/src/app

COPY . .
RUN go mod download

RUN go build -v -o /usr/local/bin/app .

CMD ["app"]
