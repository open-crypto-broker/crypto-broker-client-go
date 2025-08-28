# This Dockerfile builds server

## Build
FROM golang:alpine AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN  go mod download

COPY . .

WORKDIR /app/cli
RUN go build -o app ./cmd/test-app

## Deploy
FROM alpine

WORKDIR /app

COPY --from=build /app/cli/app .

ENTRYPOINT ["./app"]