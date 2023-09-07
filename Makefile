include .env
build:
	@go build -o bin/mysocks


run: build
	./bin/mysocks  \
		--server-url=${SERVER_URL} --password=${PASSWORD} \
		--port=${PORT} --cipher=${CIPHER}

debug: build
	DEBUG=1 ./bin/mysocks  \
		--server-url=${SERVER_URL} --password=${PASSWORD} \
		--port=${PORT} --cipher=${CIPHER}


