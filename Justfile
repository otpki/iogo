set dotenv-load := false

default:
    @just --list

test:
    go test -timeout 5m ./...

test-ci:
    go test -timeout 5m -short ./...

lint:
    go vet ./...