package client

import (
	"errors"
	"io"
	"net"

	"github.com/nzhl/mysocks/logger"
)

func parseAddr(client net.Conn) ([]byte, error) {
	if err := auth(client); err != nil {
		logger.Debug("auth error: %s", err.Error())
		return nil, err
	}

	addr, err := connect(client)
	if err != nil {
		logger.Debug("connect error: %s", err.Error())
		return nil, err
	}

	return addr, nil
}

func auth(client net.Conn) (err error) {
	buf := make([]byte, 256)

	// VER & NMETHODS
	n, err := io.ReadFull(client, buf[:2])
	if n != 2 {
		return errors.New("reading header: " + err.Error())
	}

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	// METHODS
	n, err = io.ReadFull(client, buf[:nMethods])
	if n != nMethods {
		return errors.New("reading methods: " + err.Error())
	}

	// SKIP AUTH
	n, err = client.Write([]byte{0x05, 0x00})
	if n != 2 || err != nil {
		return errors.New("write rsp: " + err.Error())
	}

	return nil
}

func connect(client net.Conn) ([]byte, error) {
	buf := make([]byte, 256)

	n, err := io.ReadFull(client, buf[:4])
	if n != 4 {
		return nil, errors.New("read header: " + err.Error())
	}

	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 || cmd != 1 {
		return nil, errors.New("invalid ver/cmd")
	}

	addr := []byte{atyp}
	switch atyp {
	case 1:
		n, err = io.ReadFull(client, buf[:4])
		if n != 4 {
			return nil, errors.New("invalid IPv4: " + err.Error())
		}
		addr = append(addr, buf[:4]...)
	case 3:

		n, err = io.ReadFull(client, buf[:1])
		if n != 1 {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addr = append(addr, buf[:1]...)

		addrLen := int(buf[0])
		n, err = io.ReadFull(client, buf[:addrLen])
		if n != addrLen {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addr = append(addr, buf[:addrLen]...)

	case 4:
		return nil, errors.New("IPv6: no supported yet")

	default:
		return nil, errors.New("invalid atyp")
	}

	n, err = io.ReadFull(client, buf[:2])
	if n != 2 {
		return nil, errors.New("read port: " + err.Error())
	}
	addr = append(addr, buf[:2]...)

	// told client we are ready to go
	_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return nil, errors.New("write rsp: " + err.Error())
	}

	return addr, nil
}
