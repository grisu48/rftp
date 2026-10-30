.PHONY: all test
default: all

all: rftp
rftp: cmd/rftp/*.go
	go build -o $@ $^

test:
	go build -o rftp ./cmd/rftp
	go vet ./...
	gofmt -l .
	go test ./...

container: Containerfile cmd/rftp/*.go
	podman build . -t localhost/rftp