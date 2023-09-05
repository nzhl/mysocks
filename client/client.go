package client

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/nzhl/mysocks/ciphers"
	"github.com/nzhl/mysocks/logger"
)

type Config struct {
	server   string
	password string
	port     string
	cipher   string
}

type Client struct {
	config Config
	cipher ciphers.AEADCipher
}

func New() *Client {
	client := &Client{}

	flag.StringVar(&client.config.server, "server-url", "", "remote ss-server address")
	flag.StringVar(&client.config.password, "password", "", "remote ss-server password")
	flag.StringVar(&client.config.port, "port", "8888", "port number you are listen to")
	flag.StringVar(&client.config.cipher, "cipher", "aes-128-gcm", "cipher method i.e. aes-128-gcm")
	flag.Parse()
	logger.Debug("Parsed Config: %+v \n", client.config)

	if client.config.server == "" {
		fmt.Println("server-url is required")
		os.Exit(1)
	}

	if client.config.password == "" {
		fmt.Println("server-password is required")
		os.Exit(1)
	}

	cipher, err := ciphers.NewAEADCipher(client.config.cipher, client.config.password)
	if err != nil {
		fmt.Println("cipher is not supported ", err.Error())
		os.Exit(1)
	}
	client.cipher = cipher

	return client
}

func (c *Client) Listen() {
	port := c.config.port

	fmt.Printf("listening on port %s...\n", port)
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Debug("connection error: %s", err.Error())
			continue
		}
		logger.Debug("incoming connection from %s", conn.RemoteAddr().String())

		go c.handle(conn)
	}
}

func (c *Client) handle(socks5Conn net.Conn) {
	defer socks5Conn.Close()
	// auth, connect and then parse remote targetAddr:port
	targetAddr, err := parseAddr(socks5Conn)
	if err != nil {
		logger.Debug("socks5 failed to parse: %s", err.Error())
		return
	}

	// forward msg to ss-server
	proxyServerAddr, err := net.ResolveTCPAddr("tcp", c.config.server)
	if err != nil {
		logger.Debug("Error resolving proxy server address: %s", err.Error())
		return
	}
	logger.Debug("targetAddr: %s", proxyServerAddr.String())

	ssConn, err := net.DialTCP("tcp", nil, proxyServerAddr)
	if err != nil {
		logger.Debug("Failed to connect to proxy server: %s", err.Error())
		return
	}
	defer ssConn.Close()

	shadowedConn := ciphers.NewShadowConn(ssConn, c.cipher)

	// 1.1 Addressing, Addresses used in Shadowsocks follow the socks5 address format
	// 1.2 TCP, [target address][payload]
	shadowedConn.Write(targetAddr)

	// TOOD: relay between socsk5 and shadow connnection
}
