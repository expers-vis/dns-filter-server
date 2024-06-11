SRC=main.go
BIN=dns-filter

all: build

format:
	go fmt ./...
	go vet ./...

build:
	go build -o ${BIN} ${SRC}

run: build
	./${BIN}

clean:
	go clean
	rm ${BIN}
