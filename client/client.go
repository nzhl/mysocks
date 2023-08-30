package client

import (
	"fmt"
	"net"
	"os"
	"sync"

	_ "github.com/joho/godotenv/autoload"
	"github.com/nzhl/mysocks/ciphers"
	"github.com/nzhl/mysocks/socks5"
)

func Listen(port string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}

		go handle(conn)
	}
}

func handle(socks5Conn net.Conn) {
	defer socks5Conn.Close()
	// auth, connect and then parse remote targetAddr:port
	targetAddr, err := socks5.Process(socks5Conn)
	if err != nil {
		fmt.Println("socks5 failed to parse:", err)
		return
	}

	// forward msg to ss-server
	proxyServerEnv := os.Getenv("PROXY_SERVER")
	proxyServerAddr, err := net.ResolveTCPAddr("tcp", proxyServerEnv)
	if err != nil {
		fmt.Println("Error resolving proxy server address:", err.Error())
		return
	}
	ssConn, err := net.DialTCP("tcp", nil, proxyServerAddr)
	if err != nil {
		fmt.Println("Failed to connect to proxy server:", err.Error())
		return
	}
	defer ssConn.Close()

	var wg sync.WaitGroup

	// forward info between
	// socks5Conn <=> ssConn
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := ciphers.Encode(socks5Conn, ssConn, targetAddr)
		if err != nil {
			fmt.Println("Error encoding message:", err.Error())
			return
		}
		ssConn.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		err = ciphers.Decode(ssConn, socks5Conn)
		if err != nil {
			fmt.Println("Error decoding message:", err.Error())
			return
		}
		ssConn.CloseRead()
	}()

	wg.Wait()

}
