FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN go mod tidy && go mod download && go build -o app

FROM alpine:3.20
WORKDIR /app
ENV SERVICE_NAME=secret-manager
COPY --from=build /src/app /app/app
EXPOSE 8080
CMD ["/app/app"]
