package dns_filter_server

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const BUFFER_SIZE uint16 = 1024

type DNSFilterServer struct {
	IP        string
	Port      uint16
	IpVersion uint8

	externalServer     string
	externalServerAddr *net.UDPAddr
	socket             net.PacketConn
	logger             *Logger
}

func NewDNSServer(ip string, port uint16, ipVersion uint8) (*DNSFilterServer, error) {
	server := DNSFilterServer{
		IP:        ip,
		Port:      port,
		IpVersion: ipVersion,
	}

	log, err := NewLogger()

	if err != nil {
		return nil, err
	}

	server.logger = log

	server.logger.log.Infoln("Creating DNS Filter server...")

	// TODO: add support for actually setting external server
	err = server.resolveExternalServer()

	if err != nil {
		return nil, err
	}

	server.logger.log.Infoln("Created DNS Filter server")

	return &server, nil
}

func (server *DNSFilterServer) Start() error {
	socket, err := server.getSocket()

	if err != nil {
		return err
	}

	server.socket = socket
	defer server.socket.Close()

	buffer := make([]byte, BUFFER_SIZE)

	server.logger.log.Infof("DNS Filter server has started")

	for {
		bytes_read, addr, err := server.socket.ReadFrom(buffer)

		if err != nil {
			server.logger.log.Warnf("Error receiving packet from %s, reason: %s", addr.String(), err.Error())
			continue
		}

		server.logger.log.Infof("Received %d bytes from %s\n", bytes_read, addr)

		// TODO: good place for Goroutine
		server.handle(buffer, addr)
	}
}

func (server *DNSFilterServer) resolveExternalServer() error {
	if server.externalServer == "" {
		server.externalServer = "8.8.8.8"
	}

	server.logger.log.Infof("Resolving external DNS server address %s:53", server.externalServer)

	externalAddr, err := net.ResolveUDPAddr(
		"udp4",
		server.externalServer+":53",
	)

	if err != nil {
		server.logger.log.Fatalf("Failed resolving external DNS server address: %s", err.Error())
		return err
	}

	server.logger.log.Infoln("Successfully resolved external DNS server address")

	server.externalServerAddr = externalAddr

	return nil
}

func (server *DNSFilterServer) getSocket() (net.PacketConn, error) {
	var address string = server.IP + ":" + fmt.Sprint(server.Port)
	var network string
	if server.IpVersion == 4 {
		network = "udp4"
	} else {
		network = "udp6"
	}

	server.logger.log.Infof(
		"Opening server socket on address %s using IPv%d", address, server.IpVersion)

	socket, err := net.ListenPacket(network, address)

	if err != nil {
		server.logger.log.Fatalf("Error creating socket: %s", err.Error())
		return nil, err
	}

	server.logger.log.Infof("Successfully opened server socket")

	return socket, nil
}

func (server *DNSFilterServer) handle(packet []byte, sender net.Addr) {
	queryID, err := server.getQueryID(packet)

	// on error queryID will be 0
	server.logger.StartQueryLog(queryID)
	defer server.logger.FinishQueryLog(queryID)

	if err != nil {
		server.logger.AddToQueryLog(queryID, "Error on initial packet parsing: "+err.Error(), "error")
		server.sendServerFailure(queryID, sender)
		return
	}

	msg, dns_err := server.handleRequest(packet)

	if dns_err != nil {
		if dns_err.Filtered() {
			server.logger.AddToQueryLog(queryID, "Refusing query for: "+dns_err.Error(), "info")
			refuseErr := server.refuseRequest(packet, sender)

			if refuseErr == nil {
				server.logger.AddToQueryLog(queryID, "Refused and sent back.", "info")
				return
			} else {
				server.logger.AddToQueryLog(queryID, "Unable to refuse: "+refuseErr.Error(), "error")
			}
		} else {
			server.logger.AddToQueryLog(queryID, "Error during handling the request message: "+dns_err.Error(), "error")
		}

		server.sendServerFailure(queryID, sender)
		return
	}

	return_msg, dns_err := server.getExternalResolution(queryID, msg)

	if dns_err != nil {
		server.logger.AddToQueryLog(queryID, "Error while getting external resolution: "+dns_err.Error(), "error")
		server.sendServerFailure(queryID, sender)
		return
	}

	dns_err = server.handleResponse(return_msg, sender)

	if dns_err != nil {
		server.logger.AddToQueryLog(queryID, "Error while returning query: "+dns_err.Error(), "error")
		server.sendServerFailure(queryID, sender)
	} else {
		server.logger.AddToQueryLog(queryID, "Returned query to "+sender.String(), "info")
	}
}

func (server *DNSFilterServer) handleRequest(msg []byte) ([]byte, *dns_error) {
	header, questions, err := server.parseQuery(msg)

	if err != nil {
		return nil, NewDNSError("error parsing query: "+err.Error(), false)
	}

	// only single questions are supported
	if len(questions) != 1 {
		// will be refused and sent back
		return nil, NewDNSError("too many questions", true)
	}

	// TODO: filter here

	new_msg, err := server.rebuildQuery(header, questions)

	if err != nil {
		return nil, NewDNSError("error rebuilding query: "+err.Error(), false)
	}

	return new_msg, nil
}

func (server *DNSFilterServer) handleResponse(msg []byte, senderAddr net.Addr) *dns_error {
	_, _, err := server.parseResponse(msg)

	if err != nil {
		return NewDNSError("error parsing DNS response: "+err.Error(), false)

	}

	_, err = server.socket.WriteTo(msg, senderAddr)

	if err != nil {
		return NewDNSError("error sending DNS response message: "+err.Error(), false)
	}

	return nil
}

func (server *DNSFilterServer) getExternalResolution(queryID uint16, msg []byte) ([]byte, *dns_error) {
	extConn, err := net.Dial("udp4", server.externalServer+":53")

	if err != nil {
		return nil, NewDNSError("error establishing UDP dial: "+err.Error(), false)
	}
	server.logger.AddToQueryLog(queryID, "Established UDP dial: "+extConn.LocalAddr().String(), "info")

	defer extConn.Close()

	_, err = extConn.Write(msg)

	if err != nil {
		return nil, NewDNSError("error sending DNS query message: "+err.Error(), false)
	}
	server.logger.AddToQueryLog(queryID, "Sent DNS query message to public server "+server.externalServer, "info")

	extConn.SetReadDeadline(time.Now().Add(3 * time.Second))

	buffer := make([]byte, BUFFER_SIZE)

	n, err := extConn.Read(buffer)

	if err != nil {
		return nil, NewDNSError("error receiving DNS response: "+err.Error(), false)
	}
	server.logger.AddToQueryLog(queryID, "Received a DNS response from public server", "info")

	return buffer[:n], nil
}

func (server *DNSFilterServer) refuseRequest(msg []byte, senderAddr net.Addr) *dns_error {
	header, questions, err := server.parseQuery(msg)

	if err != nil {
		return NewDNSError("error parsing query: "+err.Error(), false)
	}

	// mark as refused and as a response
	header.RCode = dnsmessage.RCodeRefused
	header.Response = true

	new_msg, err := server.rebuildQuery(header, questions)

	if err != nil {
		return NewDNSError("error rebuilding query: "+err.Error(), false)
	}

	_, err = server.socket.WriteTo(new_msg, senderAddr)

	if err != nil {
		return NewDNSError("error sending DNS message: "+err.Error(), false)
	}

	return nil
}

func (server *DNSFilterServer) sendServerFailure(queryID uint16, senderAddr net.Addr) {
	header := dnsmessage.Header{
		ID:       queryID,
		RCode:    dnsmessage.RCodeServerFailure,
		Response: true,
	}

	builder := dnsmessage.NewBuilder(nil, header)

	msg, err := builder.Finish()

	if err != nil {
		server.logger.AddToQueryLog(queryID, "Failed to create Server Failure message", "error")
		return
	}

	_, err = server.socket.WriteTo(msg, senderAddr)

	if err != nil {
		server.logger.AddToQueryLog(queryID, "Failed to send Server Failure message", "error")
	} else {
		server.logger.AddToQueryLog(queryID, "Sent back Server Failure message", "info")
	}
}

func (server *DNSFilterServer) getQueryID(msg []byte) (uint16, error) {
	parser := new(dnsmessage.Parser)

	header, err := parser.Start(msg)

	if err != nil {
		return 0, err
	}

	return header.ID, nil
}

func (server *DNSFilterServer) rebuildQuery(header dnsmessage.Header, questions []dnsmessage.Question) ([]byte, error) {
	question := questions[0]

	builder := dnsmessage.NewBuilder(nil, header)
	builder.StartQuestions()
	builder.Question(question)
	msg, err := builder.Finish()

	if err != nil {
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
