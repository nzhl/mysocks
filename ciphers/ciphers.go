package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"os"

	"bytes"
	"encoding/binary"

	"golang.org/x/crypto/hkdf"
)

const TAG_LENGTH = 16
const LEN_LENGTH = 2

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func evpBytesToKey(keyLen int) (key []byte) {
	password := os.Getenv("PROXY_PASSWORD")
	const md5Len = 16

	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, md5sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], md5sum(d))
	}
	return m[:keyLen]
}

func hkdfSha1(masterKey []byte, salt []byte) []byte {
	// Define your salt and input keying material, ikm
	// As an example we use simple strings, convert them to byte slices
	// salt := []byte("your-salt")

	// Create a new HMAC-based Extract-and-Expand Key Derivation Function (HKDF) with SHA-1
	hkdf := hkdf.New(sha1.New, masterKey, salt, []byte("ss-subkey"))

	// Define the length for the output key
	length := 16 // e.g., 16 bytes for an AES key.

	// Extract the derived key
	key := make([]byte, length)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}

	return key
}

func genSalt() []byte {
	salt := make([]byte, 16) // Change the size according to your needs.

	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		panic(err)
	}

	return salt
}

func numToBytes(n int, order binary.ByteOrder, size int) []byte {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, order, uint16(n))
	if err != nil {
		panic(err)
	}

	b := buf.Bytes()

	// If the byte slice is smaller than the requested size, pad with zeros.
	if len(b) < size {
		padding := make([]byte, size-len(b))
		if order == binary.BigEndian {
			// For big endian, prepend the padding.
			b = append(padding, b...)
		} else {
			// For little endian, append the padding.
			b = append(b, padding...)
		}
	}

	return b
}

// aes-128-gcm, tcp
func Encode(source io.Reader, destination io.Writer, addr []byte) error {
	key := evpBytesToKey(16)
	salt := genSalt()
	subKey := hkdfSha1(key, salt)

	// Create a new cipher block from the key.
	block, err := aes.NewCipher(subKey)
	if err != nil {
		return err
	}

	// Create a new GCM. Note that the key must be 16 bytes for AES-128.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := 0
	payload := make([]byte, 1024*10)

	// salt first
	destination.Write(salt)
	for {
		actualLen, err := source.Read(payload)
		if actualLen == 0 && err == io.EOF {
			return nil
		}
		if err != nil {
			println("error while read from socks5: ", err.Error())
			return err
		}

		if nonce == 0 {
			payload = append(addr, payload...)
			actualLen += len(addr)
		}

		cipherTextWithTag := gcm.Seal([]byte{}, numToBytes(nonce+1, binary.LittleEndian, gcm.NonceSize()), payload[:actualLen], nil)
		cipherLengthWithTag := gcm.Seal([]byte{}, numToBytes(nonce, binary.LittleEndian, gcm.NonceSize()), numToBytes(len(cipherTextWithTag)-TAG_LENGTH, binary.BigEndian, LEN_LENGTH), nil)

		// write to destination
		_, err = destination.Write(append(cipherLengthWithTag, cipherTextWithTag...))
		if err != nil {
			println("error while write to ssserver: ", err)
			return err
		}
		nonce += 2
	}
}

func Decode(source io.Reader, destination io.Writer) error {
	key := evpBytesToKey(16)
	salt := make([]byte, 16)
	actualLen, err := io.ReadFull(source, salt)
	if actualLen != 16 {
		return err
	}
	subKey := hkdfSha1(key, salt)

	// Create a new cipher block from the key.
	block, err := aes.NewCipher(subKey)
	if err != nil {
		return err
	}

	// Create a new GCM. Note that the key must be 16 bytes for AES-128.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := 0
	for {
		cipherLengthWithTag := make([]byte, LEN_LENGTH+TAG_LENGTH)
		actualLen, err := io.ReadFull(source, cipherLengthWithTag)
		if actualLen == 0 && err == io.EOF {
			return nil
		}
		if actualLen != LEN_LENGTH+TAG_LENGTH {
			println("error while read payload length: ", err.Error())
			return err
		}

		lenBytes, err := gcm.Open(cipherLengthWithTag[:0], numToBytes(nonce, binary.LittleEndian, gcm.NonceSize()), cipherLengthWithTag, nil)
		if err != nil {
			println("decrypt length err: ", err.Error())
			return err
		}
		encryptedPayloadLen := int(binary.BigEndian.Uint16(lenBytes))

		encryptedPayloadWithTag := make([]byte, encryptedPayloadLen+TAG_LENGTH)
		actualLen, err = io.ReadFull(source, encryptedPayloadWithTag)
		if actualLen != encryptedPayloadLen+TAG_LENGTH {
			println("error while read payload: ", err.Error())
			return err
		}

		payload, err := gcm.Open(encryptedPayloadWithTag[:0], numToBytes(nonce+1, binary.LittleEndian, gcm.NonceSize()), encryptedPayloadWithTag, nil)
		if err != nil {
			println("decrypt payload error: ", err)
			return err
		}
		_, err = destination.Write(payload)
		if err != nil {
			println("error while write to socks5 ", err)
			return err
		}
		nonce += 2
	}
}
