.PHONY: build build-all test clean

BINARY := subtakeover
GO := go

build:
	$(GO) build -o $(BINARY) ./cmd/subtakeover

build-all:
	GOOS=linux   GOARCH=amd64 $(GO) build -o $(BINARY)-linux-amd64   ./cmd/subtakeover
	GOOS=darwin  GOARCH=arm64 $(GO) build -o $(BINARY)-darwin-arm64  ./cmd/subtakeover
	GOOS=windows GOARCH=amd64 $(GO) build -o $(BINARY)-windows-amd64.exe ./cmd/subtakeover

test:
	$(GO) test ./internal/... -race -count=1

clean:
	rm -f $(BINARY) $(BINARY)-*
