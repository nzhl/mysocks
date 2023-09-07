package ciphers

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"

	"github.com/nzhl/mysocks/logger"
)

type AEADCipher interface {
	KeySize() int
	SaltSize() int
	NonceSize() int
	TagSize() int

	// singleton cipher during the whole app lifecycle
	// but salt differs for each connection
	Encrypter(salt []byte) (cipher.AEAD, error)
	Decrypter(salt []byte) (cipher.AEAD, error)

	GenSalt() ([]byte, error)
	GenNonce() []byte
}

// ShadowConn is a wrapper around a net.Conn
// that encrypts/decrypts all data passing through it.
type ShadowConn struct {
	net.Conn

	cipher AEADCipher

	encrypter         cipher.AEAD
	decrypter         cipher.AEAD
	nonceForEncrypter []byte
	nonceForDecrypter []byte

	readBuf []byte
}

var maxPayloadLength = 16*1024 - 1
var payloadLengthSize = 2

func (c *ShadowConn) Read(b []byte) (total int, err error) {
	logger.Debug("trying to read %d bytes from shadow connection", len(b))
	if c.decrypter == nil {
		salt := make([]byte, c.cipher.SaltSize())
		n, err := io.ReadFull(c.Conn, salt)
		if n != c.cipher.SaltSize() {
			return total, err
		}

		c.decrypter, err = c.cipher.Decrypter(salt)
		if err != nil {
			return total, err
		}

		c.nonceForDecrypter = c.cipher.GenNonce()
		c.readBuf = make([]byte, 0, maxPayloadLength)
	}

	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]

		return n, nil
	}

	payload := make([]byte, payloadLengthSize+2*c.cipher.TagSize()+maxPayloadLength)
	_, err = io.ReadFull(c.Conn, payload[:payloadLengthSize+c.cipher.TagSize()])
	if err != nil {
		return total, err
	}

	lenBytes, err := c.decrypter.Open(payload[:0], c.nonceForDecrypter, payload[:payloadLengthSize+c.cipher.TagSize()], nil)
	if err != nil {
		logger.Debug("decrypt length err: %s", err.Error())
		return total, err
	}
	incrementNonce(c.nonceForDecrypter)

	payloadLength := int(binary.BigEndian.Uint16(lenBytes))
	logger.Debug("decrypt length: %d", payloadLength)
	_, err = io.ReadFull(c.Conn, payload[:payloadLength+c.cipher.TagSize()])
	if err != nil {
		logger.Debug("error while read payload: %s", err.Error())
		return total, err
	}

	dst := b
	if payloadLength > len(b) {
		c.readBuf = make([]byte, payloadLength)
		dst = c.readBuf
	}
	_, err = c.decrypter.Open(dst[:0], c.nonceForDecrypter, payload[:payloadLength+c.cipher.TagSize()], nil)
	if err != nil {
		println("decrypt payload error: ", err)
		return total, err
	}
	incrementNonce(c.nonceForDecrypter)

	if payloadLength > len(b) {
		n := copy(b, dst)
		c.readBuf = c.readBuf[n:]
		total += n
	} else {
		total += payloadLength
	}

	logger.Debug("read %d bytes from shadow connection", total)
	return total, nil
}

// 3.3 TCP
// An AEAD encrypted TCP stream starts with a randomly generated salt to
// derive the per-session subkey, followed by any number of encrypted chunks.
// Each chunk has the following structure:
// [encrypted payload length][length tag][encrypted payload][payload tag]

func (c *ShadowConn) Write(b []byte) (total int, err error) {
	logger.Debug("trying to write %d bytes to shadow connection", len(b))
	if c.encrypter == nil {
		salt, nil := c.cipher.GenSalt()
		if err != nil {
			return 0, err
		}
		c.encrypter, err = c.cipher.Encrypter(salt)
		if err != nil {
			return 0, err
		}

		n, err := c.Conn.Write(salt)
		if err != nil {
			return n, err
		}
		total += n

		c.nonceForEncrypter = c.cipher.GenNonce()
	}

	// 3.3 TCP
	// Payload length is a 2-byte big-endian unsigned integer capped at 0x3FFF.
	// The higher two bits are reserved and must be set to zero.
	// Payload is therefore limited to 16*1024 - 1 bytes
	payload := make([]byte, payloadLengthSize+2*c.cipher.TagSize()+maxPayloadLength)
	for cursor := 0; cursor < len(b); cursor += maxPayloadLength {
		payloadLength := maxPayloadLength
		if len(b[cursor:]) < maxPayloadLength {
			payloadLength = len(b[cursor:])
		}

		// big-endian payload size
		payload[0], payload[1] = byte(payloadLength>>8), byte(payloadLength)

		c.encrypter.Seal(payload[:0], c.nonceForEncrypter, payload[:payloadLengthSize], nil)
		incrementNonce(c.nonceForEncrypter)

		c.encrypter.Seal(payload[:payloadLengthSize+c.cipher.TagSize()], c.nonceForEncrypter, b[cursor:cursor+payloadLength], nil)
		incrementNonce(c.nonceForEncrypter)

		n, err := c.Conn.Write(payload[:payloadLengthSize+2*c.cipher.TagSize()+payloadLength])
		if err != nil {
			return total + n, err
		}
		total += n
	}

	return total, nil
}

func NewShadowConn(conn net.Conn, cipher AEADCipher) net.Conn {
	return &ShadowConn{Conn: conn, cipher: cipher}
}
