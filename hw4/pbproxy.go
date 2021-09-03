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
	"log"
	"net"
	"os"
	"strings"
)

func Client(addr string, passPhrase []byte) {
	conn, err := net.Dial("tcp", addr)
	log.Printf("[CLIENT] org: %s\n", conn.LocalAddr().String())
	log.Printf("[CLIENT] dst: %s\n", conn.RemoteAddr().String())
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()
	go func() {
		for {
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err == io.EOF {
				continue
			}
			log.Printf("[CLIENT] receive: %d\n", n)
			recv := buf[:n]
			log.Printf("[CLIENT] received(encrypted): %v", recv)
			// decrypt response
			//msg, err := extractMsg(recv, passPhrase)
			msg := recv // TODO: testOnly
			if err != nil {
				log.Println(err)
			}
			log.Printf("[CLIENT] received(decrypted): %v", string(msg))
		}
	}()
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		msg := scanner.Bytes()
		msg = append(msg, '\n')
		// combine user input, nonce and salt together
		// msg := generateMsg(buf[:n1], passPhrase)		// TODO: testOnly
		//if len(msg) == 0 {
		//	continue
		//}
		_, err := conn.Write(msg)
		//log.Printf("[CLIENT] input: %d, relay(Encrypted) %d\n", n1, n2)
		log.Printf("[CLIENT] input: %s\n", string(msg))

		if err != nil {
			log.Println(err)
			continue
		}
	}
}

func ReverseProxy(listenPort string, forwardAddr string, passPhrase []byte) {
	listener, err := net.Listen("tcp", listenPort)
	if err != nil {
		log.Fatal("[SERVER] tcp server listener error:", err)
	}
	for {
		// accept new connection
		listenConn, _ := listener.Accept()
		target, _ := net.Dial("tcp", forwardAddr)
		log.Printf("[SERVER] accepted: %s\n", listenConn.RemoteAddr().String())
		log.Printf("[SERVER] org: %s\n", target.LocalAddr().String())
		log.Printf("[SERVER] dst: %s\n", target.RemoteAddr().String())

		defer listenConn.Close()
		defer target.Close()

		go SocketServer(listenConn, target, true, passPhrase)  // decode data and relay to the dst addr
		go SocketServer(target, listenConn, false, passPhrase) // encrypt response and return
		//go io.Copy(target, listenConn)
		//go io.Copy(listenConn, target)
	}
}

func SocketServer(from net.Conn, to net.Conn, outbound bool, passPhrase []byte) {
	for {
		buffer := make([]byte, 4096)
		n1, err := from.Read(buffer)
		if err != nil {
			log.Println(err)
			return
		}
		log.Printf("[SERVER] recv %d from: %s\n", n1, from.RemoteAddr().String())
		var recv = buffer[:n1]
		var msg []byte
		//if outbound {
		//	msg, err = extractMsg(recv, passPhrase) // decrypt messages
		//	if err != nil {
		//		log.Println(err)
		//		log.Println("[SERVER] Verification failed, turn to garbage.")
		//		continue
		//	}
		//} else {
		//	msg = generateMsg(recv, passPhrase) // encrypt responses from dst addr
		//}
		msg = recv // TODO: testOnly
		n2, err := to.Write(msg)
		log.Printf("[SERVER] write: %d to: %s\n", n2, to.RemoteAddr().String())
		if err != nil {
			log.Println(err)
			return
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
	log.Printf("Key: %s\n", key) // TODO: SERVER or CLIENT
	log.Printf("Ciphertext: %s\n", ciphertext)
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
		log.Printf("Decrypt error: %s\n", err.Error()) // TODO: SERVER or CLIENT
		return nil, err
	}
	log.Printf("plainText: %s\n", plainText)
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

// TODO: unit test of Encrypt and Decrypt

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
	//passPhrase, _ := ioutil.ReadFile(keyPath)
	passPhrase := []byte{} // TODO: testOnly

	if listenPort != "" {
		ReverseProxy(":"+listenPort, addr, passPhrase)
	} else {
		Client(addr, passPhrase)
	}

}
