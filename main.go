package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const (
	MAX_TTL = 30
	PORT = 33434
)

func main() {
	if len(os.Args) < 1 {
		fmt.Printf("dst is not set.")
		os.Exit(1)
	}
	dst := os.Args[1]
	// resolve domain addr
	addr, err := resolveDstDomain(dst)
	if err != nil {
		panic(err)
	}
	fmt.Printf("go-traceroute to %s(%s) 30 max hops\n", dst, addrString(addr))
	if err := handle(addr); err != nil {
		panic(err)
	}
	os.Exit(0)
}

func handle(dst [4]byte) error {
	// open udp socket to send udp datagram
	udpSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return err
	}
	// open raw socket to recieve icmp packet.
	icmpSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	defer syscall.Close(udpSocket)
	defer syscall.Close(icmpSocket)

	// ip packet time val
	timeval := syscall.NsecToTimeval(1000 * 1000 * (int64)(2000))
	myAddr, err := mySockAddr()
	if err != nil {
		return err
	}
	// loop
	prevAddr := ""
	for ttl := 1; ttl < MAX_TTL; ttl++ {
		port := PORT + (ttl - 1)
		// set ttl, timeval
		if err := syscall.SetsockoptInt(udpSocket, 0x0, syscall.IP_TTL, ttl); err != nil {
			return err
		}
		if err := syscall.SetsockoptTimeval(icmpSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeval); err != nil {
			return err
		}
		// bind icmp socket
		if err := syscall.Bind(icmpSocket, &syscall.SockaddrInet4{Port: PORT, Addr: myAddr}); err != nil {
			return err
		}
		// send udp packet set ttl
		if err := syscall.Sendto(udpSocket, []byte{0x0}, 0, &syscall.SockaddrInet4{Port: port, Addr: dst}); err != nil {
			return err
		}

		fmt.Printf("%2d  ", ttl)
		// recv icmp rep
		rep := make([]byte, 60)
		_, from, err := syscall.Recvfrom(icmpSocket, rep, 0)
		if err != nil {
			fmt.Println("recvfrom error")
			return err
		}
		switch f := from.(type) {
		case *syscall.SockaddrInet4:
			hopDomain := resolveHopAddr(f.Addr)
			fmt.Printf("%s(%s),", hopDomain, addrString(f.Addr))
			if prevAddr == addrString(f.Addr) {
				return nil
			}
			prevAddr = addrString(f.Addr)
		default:
			return fmt.Errorf("unsupported inet addr type")
		}
		fmt.Printf("\n")
	}
	return nil
}

func resolveDstDomain(domain string) ([4]byte, error) {
	// lookup addresses from local resolver
	addr := [4]byte{0,0,0,0}
	addrs, err := net.LookupHost(domain) // addrs is slice
	if err != nil {
		return addr, err
	}
	// pick first one
	addrStr := addrs[0]
	b := strings.Split(addrStr, ".")
	for i, bb := range b {
		n, err := strconv.Atoi(bb)
		if err != nil {
			return addr, err
		}
		addr[i] = byte(n)
	}
	return addr, nil
}

func resolveHopAddr(addr [4]byte) string {
	domains, err := net.LookupAddr(addrString(addr))
	if err != nil {
		return addrString(addr)
	}
	return domains[0]
}

func mySockAddr() ([4]byte, error) {
	addr := [4]byte{0,0,0,0}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return addr, err
	}
	// check ipv4 and not loopback
	for _, ifaceAddr := range addrs {
		if ipnet, ok := ifaceAddr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if len(ipnet.IP.To4()) == net.IPv4len {
				copy(addr[:], ipnet.IP.To4())
				return addr, nil
			}
		}
	}
	return [4]byte{0,0,0,0}, fmt.Errorf("failed to get an available interface.")
}

func addrString(addr [4]byte) string {
	return fmt.Sprintf("%v.%v.%v.%v", addr[0], addr[1], addr[2], addr[3])
}
