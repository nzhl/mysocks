package ciphers

import (
	"bytes"
	"testing"
)

func TestEvpBytesToKey(t *testing.T) {
	key := evpBytesToKey("123456", 16)
	isEqual := bytes.Compare(key, []byte{225, 10, 220, 57, 73, 186, 89, 171, 190, 86, 224, 87, 242, 15, 136, 62}) == 0
	if !isEqual {
		t.Error("EvpBytesToKey error")
	}

}
