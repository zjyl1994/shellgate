BIN := shellgate
CMD := ./cmd/shellgate

.PHONY: all build test test-race vet fmt check run init version

all: check build

build:
	go build -o $(BIN) $(CMD)

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

check: test test-race vet

init: build
	./$(BIN) init

run: build
	./$(BIN)

version: build
	./$(BIN) version
