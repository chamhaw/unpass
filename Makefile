.PHONY: build test clean tidy

build:
	go build -o bin/unpass ./cmd/cli

test:
	go test ./...

clean:
	rm -rf bin/

tidy:
	go mod tidy

install:
	go install ./cmd/cli 