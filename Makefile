.PHONY: build test verify docs snapshot clean

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

build:
	mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/mactriage ./cmd/mactriage

test:
	go test -race ./...

verify:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath ./cmd/mactriage
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath ./cmd/mactriage
	rm -f mactriage

docs:
	go run ./cmd/gen-docs docs/generated

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf bin dist docs/generated
