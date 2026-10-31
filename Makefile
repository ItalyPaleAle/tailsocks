.PHONY: test
test:
	go test ./...

.PHONY: test-race
test-race:
	CGO_ENABLED=1 go test -race ./...

.PHONY: lint
lint:
	golangci-lint run -c .golangci.yaml
