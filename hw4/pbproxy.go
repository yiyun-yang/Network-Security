package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
)

func Client(addr string, passPhrase []byte) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Print(err)
		return
	}
	defer conn.Close()
	// use goroutine to read user input and send data in non-blocking way
	go func() {
		buf := make([]byte, 4096)
		for {
			n1, err := os.Stdin.Read(buf)
			if err != nil {
				fmt.Print(err)
				continue
			}
			// combine user input, nonce and salt together
			msg := generateMsg(buf[:n1], passPhrase)
			n2, err := conn.Write(msg)
			fmt.Print(n1, n2, "send: %d, recv %d")
			if err != nil {
				fmt.Print(err)
				continue
			}
		}
	}()
	// read response sequentially
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err == io.EOF {
			continue
		}
		recv := buf[:n]
		fmt.Print(string(recv))
		// decrypt response
		msg, err := extractMsg(recv, passPhrase)
		if err != nil {
			fmt.Print(err)
		}
		fmt.Println(msg)
	}
}

// eg. listenAddr: :2222
func ServerProxy(listenAddr string, addr string, passPhrase []byte) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal("tcp server listener error:", err)
	}
	for {
		// accept new connection
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal("tcp server accept error", err)
		}
		// start a new goroutine: handle multiple concurrent connections in non-blocking way
		go HandleConnection(addr, conn, passPhrase)
	}
}

func HandleConnection(addr string, conn net.Conn, passPhrase []byte) {
	fmt.Print(conn.RemoteAddr().String(), "client connected: %s")
	target, err := net.Dial("tcp", addr)
	defer conn.Close()
	if err != nil {
		fmt.Print(err)
		// conn.Close()
	} else {
		defer target.Close()
		fmt.Print(target.LocalAddr().String(), "target connected: %s")
		// closed := make(chan bool, 2)
		go Proxy(conn, target, true, passPhrase)  // decode client data and relay to the dst addr
		go Proxy(target, conn, false, passPhrase) // encrypt response and return to the client
		// <-closed
		// fmt.Print(conn.RemoteAddr().String(), "connection closed: %s")
	}
}

// func Proxy(from net.Conn, to net.Conn, closed chan bool, out bool, passPhrase []byte) {
func Proxy(from net.Conn, to net.Conn, out bool, passPhrase []byte) {
	buffer := make([]byte, 4096)
	for {
		n1, err := from.Read(buffer)
		if err != nil {
			//closed <- true
			//return
			continue
		}
		var recv = buffer[:n1]
		var msg []byte
		if out {
			msg, err = extractMsg(recv, passPhrase) // decrypt client messages
			// TODO: verify if it works
			if err != nil {
				fmt.Print(err)
				fmt.Println("Verification failed")
				continue
			}
		} else {
			msg = generateMsg(recv, passPhrase) // encrypt responses from dst addr
		}
		n2, err := to.Write(msg)
		fmt.Print(from.RemoteAddr().String(), n1, to.RemoteAddr().String(), n2, "from: %s, recv %d. to: %s, send: %d")
		if err != nil {
			fmt.Print(err)
			//closed <- true
			//return
			continue
		}
	}
}

func generateMsg(plainText []byte, passphrase []byte) []byte {
	nonce, salt := GenerateNonceAndSalt()
	cypherText := Encrypt(plainText, passphrase, nonce, salt)
	return BytesCombine(nonce, salt, cypherText)
}

func extractMsg(recvMsg []byte, passphrase []byte) ([]byte, error) {
	nonce, salt, cypherText := recvMsg[:12], recvMsg[12:20], recvMsg[20:]
	plainText, err := Decrypt(cypherText, passphrase, nonce, salt)
	return plainText, err
}

// Using AES-256 in GCM mode
func Encrypt(plainText []byte, passphrase []byte, nonce []byte, salt []byte) []byte {
	key := GenerateKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plainText, nil)
	fmt.Printf("Key: %s\n", key)
	fmt.Printf("Ciphertext: %s\n", ciphertext)
	return ciphertext
}

func Decrypt(cipherText []byte, passphrase []byte, nonce []byte, salt []byte) ([]byte, error) {
	key := GenerateKey(passphrase, salt)
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
		fmt.Printf("Decrypt error: %s", err.Error())
		return nil, err
	}
	fmt.Printf("plainText: %s\n", plainText)
	return plainText, nil
}

// AES key was derived from the supplied passphrase using PBKDF2
func GenerateKey(passphrase []byte, salt []byte) []byte {
	// keyLen should be 32 for AES-256
	return pbkdf2.Key(passphrase, salt, 512, 32, sha1.New)
}

func GenerateNonceAndSalt() ([]byte, []byte) {
	nonce := make([]byte, 12)
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err.Error())
	}
	return nonce, salt
}

func BytesCombine(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}

func main() {
	// Parsing command lines: eg. pbproxy -p mykey -l 2222 localhost 22
	var keyPath string
	var listenPort string
	var addrArr []string
	flag.StringVar(&keyPath, "p", "", "Use the ASCII text passphrase contained in <pwdfile>")
	flag.StringVar(&listenPort, "l", "", "Reverse-proxy mode: listen for inbound connections on <listenport> and relay them to <destination>:<port>")
	flag.Parse()
	addrArr = flag.Args()
	var addr = strings.Join(addrArr, ":")
	passPhrase, _ := ioutil.ReadFile(keyPath)

	if listenPort != "" {
		ServerProxy(":"+listenPort, addr, passPhrase)
	} else {
		Client(addr, passPhrase)
	}

}
