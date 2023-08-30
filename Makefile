build:
	@go build -o bin/mysocks


run: build
	./bin/mysocks


test:
	@go test -v ./...
