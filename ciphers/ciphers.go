package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

type metaAEADCipher struct {
	keySize   int
	saltSize  int
	nonceSize int
	tagSize   int

	password string
}

// 3 AEAD Ciphers
var config = map[string]metaAEADCipher{
	"aes-128-gcm": {
		keySize:   16,
		saltSize:  16,
		nonceSize: 12,
		tagSize:   16,
	},
	"aes-192-gcm": {
		keySize:   24,
		saltSize:  24,
		nonceSize: 12,
		tagSize:   16,
	},
	"aes-256-gcm": {
		keySize:   32,
		saltSize:  32,
		nonceSize: 12,
		tagSize:   16,
	},
}

func NewAEADCipher(name, password string) (AEADCipher, error) {
	cipher, ok := config[name]
	if !ok {
		return nil, fmt.Errorf("unsupported cipher: %s", name)
	}
	cipher.password = password

	return &cipher, nil
}

func (c *metaAEADCipher) KeySize() int {
	return c.keySize
}

func (c *metaAEADCipher) SaltSize() int {
	return c.saltSize
}

func (c *metaAEADCipher) NonceSize() int {
	return c.nonceSize
}

func (c *metaAEADCipher) TagSize() int {
	return c.tagSize
}

func (c *metaAEADCipher) Encrypter(salt []byte) (cipher.AEAD, error) {
	masterKey := evpBytesToKey(c.password, c.keySize)
	subKey, err := hkdfSha1(masterKey, salt, c.keySize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(subKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm, nil
}

func (c *metaAEADCipher) Decrypter(salt []byte) (cipher.AEAD, error) {
	masterKey := evpBytesToKey(c.password, c.keySize)
	subKey, err := hkdfSha1(masterKey, salt, c.keySize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(subKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm, nil
}

func (c *metaAEADCipher) GenSalt() ([]byte, error) {
	salt := make([]byte, c.saltSize)

	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, fmt.Errorf("error while generating salt: %s", err.Error())
	}

	return salt, nil
}

func (c *metaAEADCipher) GenNonce() []byte {
	return make([]byte, c.nonceSize)
}

// 3.1 EVP_BytesToKey
// https://www.openssl.org/docs/man1.0.2/man3/EVP_BytesToKey.html
//
//	D_i = HASH^count(D_(i-1) || data || salt)
//
// case for ss here is count=1, salt=nil
// code reference:
// https://github.com/shadowsocks/shadowsocks-go/blob/3e585ff90601765510d31ee1d05b6f63548c7d44/shadowsocks/encrypt.go#L28C2-L28C2
func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func evpBytesToKey(password string, size int) (key []byte) {
	const md5Len = 16

	cnt := (size-1)/md5Len + 1
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
	return m[:size]
}

// 3.2 HKDF_SHA1
func hkdfSha1(masterKey []byte, salt []byte, size int) ([]byte, error) {
	// Create a new HMAC-based Extract-and-Expand Key Derivation Function (HKDF) with SHA-1
	hkdf := hkdf.New(sha1.New, masterKey, salt, []byte("ss-subkey"))

	// Extract the derived key
	key := make([]byte, size)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, fmt.Errorf("error while generating subKey: %s", err.Error())
	}

	return key, nil
}

// 3.3 TCP
// The first AEAD encrypt/decrypt operation uses a counting nonce starting
// from 0. After each encrypt/decrypt operation, the nonce is incremented
// by one as if it were an unsigned little-endian integer.
func incrementNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++

		// not carry
		if nonce[i] != 0 {
			break
		}
	}
}
