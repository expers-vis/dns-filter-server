package dns_filter_server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type query struct {
	id          uint16
	sender_addr net.Addr
}

type DNSFilterServer struct {
	IP                 string
	Port               uint16
	IpVersion          uint8
	
	externalServer     string
	externalServerAddr *net.UDPAddr
	socket             net.PacketConn
	parser             dnsmessage.Parser
	queries            []query
}

func NewDNSServer(ip string, port uint16, ipVersion uint8) *DNSFilterServer {
	server := DNSFilterServer{
		IP: ip,
		Port: port,
		IpVersion: ipVersion,
	}

	// TODO: add support for actually setting external server
	server.resolveExternalServer()

	return &server
}

func (server *DNSFilterServer) Start() {
	server.socket = server.getSocket()

	defer server.socket.Close()

	buffer := make([]byte, 1024)

	for {
		bytes_read, addr, err := server.socket.ReadFrom(buffer)

		fmt.Printf("Received %d bytes from %s\n", bytes_read, addr)

		if err != nil {
			fmt.Printf("Error reading: %s", err.Error())
			continue
		}

		header, err := server.parser.Start(buffer)

		if err != nil {
			fmt.Printf("Error parsing header: %s", err.Error())
			continue
		}

		fmt.Printf("Header says:\n%s\n", header.GoString())

		// if header.Response {
		// 	server.handleResponse(buffer, header)
		// } else {
		// 	server.handleRequest(addr, header)
		// }

		server.handle(buffer, header)
	}
}

func (server *DNSFilterServer) resolveExternalServer() {
	if server.externalServer == "" {
		server.externalServer = "8.8.8.8"
	}

	externalAddr, err := net.ResolveUDPAddr(
		"udp4",
		server.externalServer+":53",
	)

	if err != nil {
		fmt.Printf("Error setting external server: %s\n", err.Error())
		os.Exit(4)
	}

	server.externalServerAddr = externalAddr
}

func (server *DNSFilterServer) getSocket() net.PacketConn {
	var address string = server.IP + ":" + fmt.Sprint(server.Port)
	var network string
	if server.IpVersion == 4 {
		network = "udp4"
	} else {
		network = "udp6"
	}

	socket, err := net.ListenPacket(network, address)

	if err != nil {
		// TODO: add logging
		fmt.Printf("Error creating socket: %s", err.Error())
		os.Exit(3)
	}

	return socket
}

func (server *DNSFilterServer) handle(msg []byte, header dnsmessage.Header) {
	// msg, err := server.rebuildDNSQuery(header)

	// if err != nil {
	// 	fmt.Printf("Error rebuilding query: %s\n", err.Error())
	// 	return
	// }

	extConn, err := net.DialUDP("udp4", nil, server.externalServerAddr)

	if err != nil {
		fmt.Printf("Error establishing UDP dial: %s\n", err.Error())
	}

	defer extConn.Close()

	_, err = extConn.Write(msg)

	if err != nil {
		fmt.Printf("Error sending DNS query message: %s\n", err.Error())
		return
	}
	fmt.Printf("Sent DNS query message.\n")

	extConn.SetReadDeadline(time.Now().Add(3 * time.Second))

	buffer := make([]byte, 1024)

	n, _, err := extConn.ReadFromUDP(buffer)

	if err != nil {
		fmt.Printf("Error receiving DNS response: %s\n", err.Error())
	}
	fmt.Printf("Received %d bytes as DNS response\n", n)

	server.handleResponse(buffer, header)
}

func (server *DNSFilterServer) rebuildDNSQuery(header dnsmessage.Header) ([]byte, error) {
	questions, err := server.parser.AllQuestions()

	if err != nil {
		fmt.Printf("Error getting questions: %s\n", err.Error())
		return nil, err
	}

	// only single questions are supported
	if len(questions) != 1 {
		// TODO: refuse and send back
		return nil, errors.New("too many questions")
	}

	// TODO: filter

	question := questions[0]
	fmt.Printf("Message:\n%s\n", question.GoString())

	builder := dnsmessage.NewBuilder(nil, header)
	builder.StartQuestions()
	builder.Question(question)
	msg, err := builder.Finish()

	if err != nil {
		fmt.Printf("Error finishing DNS message: %s\n", err.Error())
		return nil, err
	}

	return msg, nil
}

func (server *DNSFilterServer) refusePacket() {
	// TODO
}

func (server *DNSFilterServer) handleRequest(sender net.Addr, header dnsmessage.Header) {
	questions, err := server.parser.AllQuestions()

	if err != nil {
		fmt.Printf("Error getting questions: %s\n", err.Error())
		return
	}

	// only single questions are supported
	if len(questions) != 1 {
		// TODO: refuse and send back
		return
	}

	// TODO: filter

	question := questions[0]
	fmt.Printf("Message:\n%s\n", question.GoString())

	builder := dnsmessage.NewBuilder(nil, header)
	builder.StartQuestions()
	builder.Question(question)
	msg, err := builder.Finish()

	if err != nil {
		fmt.Printf("Error finishing DNS message: %s\n", err.Error())
		return
	}

	_, err = server.socket.WriteTo(msg, server.externalServerAddr)

	if err != nil {
		fmt.Printf("Error sending DNS query message: %s\n", err.Error())
		return
	}

	server.queries = append(server.queries, query{header.ID, sender})
	fmt.Printf("Sent question to external server.\n")
}

func (server *DNSFilterServer) handleResponse(msg []byte, header dnsmessage.Header) {
	query_record, err := server.getQueryByID(header.ID)

	if err != nil {
		// TODO: refuse and send back
		return
	}

	_, err = server.socket.WriteTo(msg, query_record.sender_addr)

	if err != nil {
		fmt.Printf("Error sending DNS response message: %s\n", err.Error())
		return
	}

	server.removeQueryByID(header.ID)
}

func (server *DNSFilterServer) getQueryByID(id uint16) (query, error) {
	for _, query := range server.queries {
		if query.id == id {
			return query, nil
		}
	}

	return query{}, errors.New("query record not found")
}

func (server *DNSFilterServer) removeQueryByID(id uint16) {
	var position int = -1
	var length int = len(server.queries)

	if length > 1 {
		for pos, query := range server.queries {
			if query.id == id {
				position = pos
			}
		}

		// id not in query records
		if position == -1 {
			return
		}

		server.queries[position] = server.queries[length-1]
		server.queries = server.queries[:length-1]
	} else if length == 1 {
		server.queries = []query{}
	}
}
