package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"log"
)

func generateMsg(plainText []byte, passphrase []byte) []byte {
	nonce := make([]byte, 12)
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err.Error())
	}
	cypherText := Encrypt(plainText, passphrase, nonce, salt)
	generated := bytes.Join([][]byte{nonce, salt, cypherText}, []byte{})
	log.Printf("generateMsg: %x\n", generated)
	return generated
}

func extractMsg(recvMsg []byte, passphrase []byte) ([]byte, error) {
	log.Printf("extractMsg: %x\n", recvMsg)
	nonce, salt, cypherText := recvMsg[:12], recvMsg[12:20], recvMsg[20:]
	plainText, err := Decrypt(cypherText, passphrase, nonce, salt)
	return plainText, err
}

// Encrypt using AES-256 in GCM mode
func Encrypt(plainText []byte, passphrase []byte, nonce []byte, salt []byte) []byte {
	log.Printf("[Encrypt] plainText: %x\n", plainText)
	log.Printf("[Encrypt] nonce: %x\n", nonce)
	log.Printf("[Encrypt] salt: %x\n", salt)
	key := GenerateKey(passphrase, salt) // AES key was derived from the supplied passphrase using PBKDF2
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plainText, nil)
	log.Printf("[Encrypt] AES key: %x\n", key)
	log.Printf("[Encrypt] cipherText: %x\n", ciphertext)
	return ciphertext
}

func Decrypt(cipherText []byte, passphrase []byte, nonce []byte, salt []byte) ([]byte, error) {
	log.Printf("[Decrypt] cipherText: %x\n", cipherText)
	log.Printf("[Decrypt] nonce: %x\n", nonce)
	log.Printf("[Decrypt] salt: %x\n", salt)
	key := GenerateKey(passphrase, salt)
	log.Printf("[Decrypt] AES key: %x\n", key)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plainText, err := aesgcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Printf("[Decrypt] error: %s\n", err.Error())
		return nil, err
	}
	log.Printf("[Decrypt] plainText: %x\n", plainText)
	return plainText, nil
}

func GenerateKey(passphrase []byte, salt []byte) []byte {
	// keyLen should be 32 for AES-256
	return pbkdf2.Key(passphrase, salt, 512, 32, sha1.New)
}
