package main

import (
	"main/dns_filter_server"
)

func main() {
	server := dns_filter_server.NewDNSServer(
		"localhost",
		3333,
		4,
	)

	server.Start()
}
