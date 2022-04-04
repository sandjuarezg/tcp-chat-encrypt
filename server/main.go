package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

const lenBuff = 1024
const args = 2
const limitConn = 2

var conns []net.Conn

func main() {
	if len(os.Args) != args {
		log.Fatal("Invalid input: [port]")
	}

	listen, err := net.Listen("tcp", fmt.Sprintf("localhost:%s", os.Args[1]))
	if err != nil {
		log.Fatal(err)
	}
	defer listen.Close()

	fmt.Printf("Listening on %s\n", listen.Addr())

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Print(err)

			return
		}

		go handleRequest(conn)
	}
}

// handleRequest Handle client request
//  @param1 (conn): connection between client and server
func handleRequest(conn net.Conn) {
	defer conn.Close()

	var (
		res   = bufio.NewReader(conn)
		reply = make([]byte, lenBuff)
	)

	// write message
	_, err := conn.Write([]byte(" - Welcome to chat - \nEnter your name: "))
	if err != nil {
		log.Print(err)

		return
	}

	// read user name
	number, err := res.Read(reply)
	if err != nil {
		log.Print(err)

		return
	}

	name := reply[:number-1]

	// append connection
	conns = append(conns, conn)

	// check number of connected users
	if len(conns) > limitConn {
		_, err = conn.Write([]byte("Chat full, try again later\n"))
		if err != nil {
			log.Print(err)

			return
		}

		return
	}

	fmt.Println(string(name), "connected")

	// generate keys
	var messKey string

	if len(conns) == limitConn {
		privateKey, publicKey, err := generateKeysInBytes()
		if err != nil {
			log.Print(err)

			return
		}

		messKey = fmt.Sprintf("\nThis is your private key:\nPRIVK-%x\n\n", privateKey)
		messKey += fmt.Sprintf("\nThis is your public key:\nPUBK-%x\n\n", publicKey)
	}

	// write message to all connections
	for _, element := range conns {
		_, err = element.Write([]byte(fmt.Sprintf(" - %s connected - \n%s", name, messKey)))
		if err != nil {
			log.Print(err)

			return
		}
	}

	for {
		reply = make([]byte, lenBuff)

		// read text to chat
		number, err = res.Read(reply)
		if err != nil || string(reply[:number-1]) == "EXIT" {
			if !errors.Is(err, io.EOF) && string(reply[:number-1]) != "EXIT" {
				log.Print(err)

				return
			}

			// remove connection from chat
			for n, element := range conns {
				if conn == element {
					conns = append(conns[:n], conns[n+1:]...)
				}

				_, err = element.Write([]byte(fmt.Sprintf(" - Bye %s - \n", name)))
				if err != nil {
					log.Print(err)

					return
				}
			}

			fmt.Println(string(name), "offline")

			return
		}

		if string(reply[:number]) == "\n" {
			continue
		}

		// write message to all connections
		for _, element := range conns {
			if element != conn {
				t := time.Now().Format(time.RFC822Z)

				_, err = element.Write([]byte(fmt.Sprintf("%s (%s): %s", name, t, reply[:number])))
				if err != nil {
					log.Print(err)

					return
				}
			}
		}
	}
}

func generateKeysInBytes() (privateKey []byte, publicKey []byte, err error) {
	auxPrivateKey, err := rsa.GenerateKey(rand.Reader, lenBuff)
	if err != nil {
		return
	}

	privateKey = x509.MarshalPKCS1PrivateKey(auxPrivateKey)

	auxPublicKey := &auxPrivateKey.PublicKey
	publicKey = x509.MarshalPKCS1PublicKey(auxPublicKey)

	return
}
