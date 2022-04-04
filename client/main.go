package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

const lenBuff = 2048
const args = 2

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

func main() {
	if len(os.Args) != args {
		log.Fatal("Insufficient arguments: [port]")
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%s", os.Args[1]))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	wait := sync.WaitGroup{}

	wait.Add(1)

	go func(wait *sync.WaitGroup) {
		defer wait.Done()

		// write on connection
		for {
			err = writeOnConn(conn)
			if err != nil {
				log.Fatal(err)
			}
		}
	}(&wait)

	// read from connection
	for {
		err = readFromConn(conn)
		if err != nil {
			log.Print(err)

			break
		}
	}

	wait.Wait()
}

// readFromConn Read message from conn (message from server or from other client)
//  @param1 (conn): connection
//
//  @return1 (err): error variable
func readFromConn(conn net.Conn) (err error) {
	reply := make([]byte, lenBuff)

	number, err := conn.Read(reply)
	if err != nil {
		if errors.Is(err, io.EOF) {
			os.Exit(0)
		}

		return
	}

	if privateKey == nil {
		fmt.Print(string(reply[:number]))

		err = getKeysFromMessage(string(reply[:number]))
		if err != nil {
			return
		}

		return
	}

	fmt.Printf("--%x\n", x509.MarshalPKCS1PrivateKey(privateKey))

	decrypt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, reply[:number], nil)
	if err != nil {
		return
	}

	fmt.Println("(s) -", string(decrypt))

	return
}

// writeOnConn Write message on conn
//  @param1 (conn): connection
//
//  @return1 (err): error variable
func writeOnConn(conn net.Conn) (err error) {
	reply := make([]byte, lenBuff)

	number, err := bufio.NewReader(os.Stdin).Read(reply)
	if err != nil {
		return
	}

	if publicKey == nil {
		_, err = conn.Write(reply[:number])
		if err != nil {
			return
		}

		return
	}

	fmt.Printf("--%x\n", x509.MarshalPKCS1PublicKey(publicKey))

	encrypt, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, reply[:number], nil)
	if err != nil {
		return
	}

	_, err = conn.Write(encrypt)
	if err != nil {
		return
	}

	return
}

func getKeysFromMessage(message string) (err error) {
	var num int

	// private
	if strings.Contains(message, "PRIVK-") {
		aux := message[strings.Index(string(message), "PRIVK-"):]
		auxPrivKey := strings.TrimPrefix(aux[:strings.Index(aux, "\n")], "PRIVK-")
		dst := make([]byte, hex.DecodedLen(len(auxPrivKey)))

		num, err = hex.Decode(dst, []byte(auxPrivKey))
		if err != nil {
			return
		}

		privateKey, err = x509.ParsePKCS1PrivateKey(dst[:num])
		if err != nil {
			return
		}
	}

	// public
	if strings.Contains(message, "PUBK-") {
		aux := message[strings.Index(message, "PUBK-"):]
		auxPubKey := strings.TrimPrefix(aux[:strings.Index(aux, "\n")], "PUBK-")
		dst := make([]byte, hex.DecodedLen(len(auxPubKey)))

		num, err = hex.Decode(dst, []byte(auxPubKey))
		if err != nil {
			return
		}

		publicKey, err = x509.ParsePKCS1PublicKey(dst[:num])
		if err != nil {
			return
		}
	}

	return
}
