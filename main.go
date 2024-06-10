package main

import (
	"fmt"
	"main/dns_filter_server"
	"os"
)

func main() {
	server, err := dns_filter_server.NewDNSServer(
		"localhost",
		3333,
		4,
	)

	if err != nil {
		fmt.Printf("Error creating server: %s\n", err.Error())
		os.Exit(1)
	}

	if err := server.Start(); err != nil {
		os.Exit(2)
	}
}
