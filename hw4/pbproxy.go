package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"flag"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
)

var bufferSize = 65536

func main() {
	// Parsing command lines: eg. pbproxy -p mykey -l 2222 localhost 22
	var keyPath string
	var listenPort string
	var addrArr []string
	var test bool
	flag.BoolVar(&test, "testmode", false, "Test mode: without encryption and decryption")
	flag.StringVar(&keyPath, "p", "", "Use the ASCII text passphrase contained in <pwdfile>")
	flag.StringVar(&listenPort, "l", "", "Reverse-proxy mode: listen for inbound connections on <listenport> and relay them to <destination>:<port>")
	flag.Parse()
	addrArr = flag.Args()
	var addr = strings.Join(addrArr, ":")
	passPhrase, _ := ioutil.ReadFile(keyPath)

	if listenPort != "" {
		ReverseProxy(":"+listenPort, addr, passPhrase, test)
	} else {
		Client(addr, passPhrase, test)
	}

}

func Client(addr string, passPhrase []byte, test bool) {
	conn, err := net.Dial("tcp", addr)
	log.Printf("[CLIENT] org: %s\n", conn.LocalAddr().String())
	log.Printf("[CLIENT] dst: %s\n", conn.RemoteAddr().String())
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()
	go func() { // receiving message
		for {
			buf := make([]byte, bufferSize)
			n, err := conn.Read(buf)
			if err == io.EOF {
				continue
			}
			recv := buf[:n]
			var msg []byte
			if test {
				msg = recv
			} else {
				log.Printf("[CLIENT][RECEIVE] encrypted message %x, len: %d", recv, n)
				msg, err = extractMsg(recv, passPhrase) // decrypt response
				log.Printf("[CLIENT][RECEIVE] decrypted message: %x", msg)
				if err != nil {
					log.Println(err)
				}
			}
			log.Printf("%s", string(msg))
		}
	}()
	reader := bufio.NewReader(os.Stdin)
	buf := make([]byte, bufferSize)
	for {
		n1, _ := reader.Read(buf)
		if test {
			conn.Write(buf[:n1])
		} else {
			msg := generateMsg(buf[:n1], passPhrase) // Encrypt message
			_, err := conn.Write(msg)
			log.Printf("[CLIENT][SEND] encrypted message: %x\n", msg)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

func ReverseProxy(listenPort string, forwardAddr string, passPhrase []byte, test bool) {
	listener, err := net.Listen("tcp", listenPort)
	if err != nil {
		log.Fatal("[SERVER] tcp server listener error:", err)
	}
	listenConn, _ := listener.Accept() // accept new connection
	target, _ := net.Dial("tcp", forwardAddr)
	log.Printf("[SERVER] accepted: %s\n", listenConn.RemoteAddr().String())
	log.Printf("[SERVER] org: %s\n", target.LocalAddr().String())
	log.Printf("[SERVER] dst: %s\n", target.RemoteAddr().String())

	defer listenConn.Close()
	defer target.Close()

	closed := make(chan bool, 2)
	go Relay(listenConn, target, true, passPhrase, test, closed)  // decode data and relay to the dst addr
	go Relay(target, listenConn, false, passPhrase, test, closed) // encrypt response and return
	<-closed
}

func Relay(from net.Conn, to net.Conn, outbound bool, passPhrase []byte, test bool, closed chan bool) {
	buffer := make([]byte, bufferSize)
	for {
		n1, err := from.Read(buffer)
		if err != nil {
			log.Println(err)
			closed <- true
			return
		}
		log.Printf("[SERVER] recv len: %d, from: %s\n", n1, from.RemoteAddr().String())
		var recv = buffer[:n1]
		var msg []byte

		if test {
			msg = recv
		} else {
			if outbound {
				msg, err = extractMsg(recv, passPhrase) // decrypt messages
				if err != nil {
					log.Println(err)
					log.Println("[SERVER] Verification failed, turn to garbage.")
					closed <- true
					continue
				}
			} else {
				msg = generateMsg(recv, passPhrase) // encrypt responses from dst addr
			}
		}
		n2, err := to.Write(msg)
		log.Printf("[SERVER] write len: %d, to: %s\n", n2, to.RemoteAddr().String())
		if err != nil {
			log.Println(err)
			closed <- true
			return
		}
	}
}

/*-------------------------------- Encryption and Decryption ------------------------------------*/
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
