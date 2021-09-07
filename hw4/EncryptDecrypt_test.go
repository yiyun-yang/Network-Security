package main

import (
	"testing"
)

var passphrase = []byte("123456")
var plainText = []byte("Hello")

func TestEncryptDecrypt(t *testing.T) {
	encrypted := generateMsg(plainText, passphrase)
	decrypted, _ := extractMsg(encrypted, passphrase)
	if !Equal(plainText, decrypted) {
		t.Errorf("decrypted result: %s", string(decrypted))
	}
}

func Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
