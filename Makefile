build:
	@go build -o ./bin/daily-mrv-guardian-service_linux ./cmd/main/main.go

run:
	@go run ./cmd/main/main.go

test:
	@go test ./...