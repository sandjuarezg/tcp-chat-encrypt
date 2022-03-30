package main

import (
	"bufio"
	"bytes"
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

	var (
		reply = make([]byte, lenBuff)
		wait  = sync.WaitGroup{}
	)

	wait.Add(1)

	go func(wait *sync.WaitGroup) {
		defer wait.Done()

		// write on connection
		for {
			number, err := bufio.NewReader(os.Stdin).Read(reply)
			if err != nil {
				log.Fatal(err)
			}

			if bytes.HasPrefix(reply[:number], []byte("PUBK-")) && publicKey == nil {
				auxPublicKey := bytes.TrimPrefix(reply[:number-1], []byte("PUBK-"))

				dst := make([]byte, hex.DecodedLen(len(auxPublicKey)))

				n, err := hex.Decode(dst, auxPublicKey)
				if err != nil {
					log.Fatal(err)
				}

				publicKey, err = x509.ParsePKCS1PublicKey(dst[:n])
				if err != nil {
					log.Fatal(err)
				}

				continue
			}

			if bytes.HasPrefix(reply[:number], []byte("PRIVK-")) && privateKey == nil {
				auxPrivateKey := bytes.TrimPrefix(reply[:number-1], []byte("PRIVK-"))

				dst := make([]byte, hex.DecodedLen(len(auxPrivateKey)))

				n, err := hex.Decode(dst, auxPrivateKey)
				if err != nil {
					log.Fatal(err)
				}

				privateKey, err = x509.ParsePKCS1PrivateKey(dst[:n])
				if err != nil {
					log.Fatal(err)
				}

				continue
			}

			err = writeOnConn(conn, reply[:number])
			if err != nil {
				log.Fatal(err)
			}
		}
	}(&wait)

	// read from connection
	for {
		err = readFromConn(conn, reply)
		if err != nil {
			log.Print(err)

			break
		}
	}

	wait.Wait()
}

// readFromConn Read message from conn (message from server or from other client)
//  @param1 (conn): connection
//  @param2 (reply): reply buffer
//
//  @return1 (err): error variable
func readFromConn(conn net.Conn, reply []byte) (err error) {
	number, err := conn.Read(reply)
	if err != nil {
		if errors.Is(err, io.EOF) {
			os.Exit(0)
		}

		return
	}

	if privateKey == nil {
		fmt.Print(string(reply[:number]))

		return
	}

	// fmt.Printf("----- de -----%x\n", x509.MarshalPKCS1PrivateKey(privateKey))

	decrypt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, reply[:number], nil)
	if err != nil {
		return
	}

	fmt.Println(string(decrypt))

	return
}

// writeOnConn Write message on conn
//  @param1 (conn): connection
//  @param2 (reply): reply buffer
//
//  @return1 (err): error variable
func writeOnConn(conn net.Conn, reply []byte) (err error) {
	if publicKey == nil {
		_, err = conn.Write(reply)
		if err != nil {
			return
		}

		return
	}

	// fmt.Printf("----- en -----%x\n", x509.MarshalPKCS1PublicKey(publicKey))

	encrypt, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, reply, nil)
	if err != nil {
		return
	}

	_, err = conn.Write(encrypt)
	if err != nil {
		return
	}

	return
}
