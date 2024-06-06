package dns_filter_server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)


const BUFFER_SIZE uint16 = 1024


type DNSFilterServer struct {
	IP                 string
	Port               uint16
	IpVersion          uint8
	
	externalServer     string
	externalServerAddr *net.UDPAddr
	socket             net.PacketConn
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

	buffer := make([]byte, BUFFER_SIZE)

	for {
		bytes_read, addr, err := server.socket.ReadFrom(buffer)

		if err != nil {
			fmt.Printf("Error reading: %s", err.Error())
			continue
		}

		fmt.Printf("Received %d bytes from %s\n", bytes_read, addr)

		// TODO: good place for Goroutine
		server.handle(buffer, addr)
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

func (server *DNSFilterServer) handle(packet []byte, sender net.Addr) {
	msg, err := server.handleRequest(packet)

	// TODO: refuse if filtered
	if err != nil {
		fmt.Printf("Error during handling the request: %s\n", err.Error())
		return
	}

	extConn, err := net.Dial("udp4", server.externalServer + ":53")

	if err != nil {
		fmt.Printf("Error establishing UDP dial: %s\n", err.Error())
	}
	fmt.Printf("Established UDP dial: %s\n", extConn.LocalAddr().String())

	defer extConn.Close()

	_, err = extConn.Write(msg)

	if err != nil {
		fmt.Printf("Error sending DNS query message: %s\n", err.Error())
		return
	}
	fmt.Printf("Sent DNS query message.\n")

	extConn.SetReadDeadline(time.Now().Add(3 * time.Second))

	buffer := make([]byte, BUFFER_SIZE)

	n, err := extConn.Read(buffer)

	if err != nil {
		fmt.Printf("Error receiving DNS response: %s\n", err.Error())
	}
	fmt.Printf("Received %d bytes as DNS response\n", n)

	// truncate the buffer
	server.handleResponse(buffer[:n], sender)
}

func (server *DNSFilterServer) handleRequest(msg []byte) ([]byte, error) {
	header, questions, err := server.parseQuery(msg)
	
	if err != nil {
		fmt.Printf("Error parsing query: %s\n", err.Error())
		return nil, err
	}

	// TODO: filter here

	new_msg, err := server.rebuildQuery(header, questions)

	if err != nil {
		fmt.Printf("Error rebuilding query: %s\n", err.Error())
		return nil, err
	}

	return new_msg, nil
}

func (server *DNSFilterServer) handleResponse(msg []byte, senderAddr net.Addr) {
	header, answers, err := server.parseResponse(msg)

	if err != nil {
		fmt.Printf("Error reading DNS response: %s\n", err.Error())
		return
	}

	fmt.Println(header.GoString())
	fmt.Println(answers)

	_, err = server.socket.WriteTo(msg, senderAddr)

	if err != nil {
		fmt.Printf("Error sending DNS response message: %s\n", err.Error())
		return
	}
	fmt.Printf("Sent back DNS query to: %s\n", senderAddr.String())
}

func (server *DNSFilterServer) refuseRequest() {
	// TODO
}

func (server *DNSFilterServer) rebuildQuery(header dnsmessage.Header, questions []dnsmessage.Question) ([]byte, error) {
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

func (server *DNSFilterServer) parseQuery(msg []byte) (dnsmessage.Header, []dnsmessage.Question, error) {
	parser := new(dnsmessage.Parser)

	header, err := parser.Start(msg)

	if err != nil {
		return dnsmessage.Header{}, nil, err
	}

	questions, err := parser.AllQuestions()

	if err != nil {
		return dnsmessage.Header{}, nil, err
	}

	return header, questions, nil
}

func (server *DNSFilterServer) parseResponse(msg []byte) (dnsmessage.Header, []dnsmessage.Resource, error) {
	parser := new(dnsmessage.Parser)

	header, err := parser.Start(msg)

	if err != nil {
		return dnsmessage.Header{}, nil, err
	}

	err = parser.SkipAllQuestions()

	if err != nil {
		return dnsmessage.Header{}, nil, err
	}

	answers, err := parser.AllAnswers()

	if err != nil {
		return dnsmessage.Header{}, nil, err
	}

	return header, answers, nil
}
