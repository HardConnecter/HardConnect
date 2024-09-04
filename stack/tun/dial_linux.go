package tun

import (
	"net"
)

func (s *Stack) DialTCP(addr *net.TCPAddr) (net.Conn, error) {
	return s.endpoint.tcpDialer.Dial("tcp4", addr.String())
}

func (s *Stack) DialUDP(addr *net.UDPAddr) (net.Conn, error) {
	return s.endpoint.udpDialer.Dial("udp4", addr.String())
}
