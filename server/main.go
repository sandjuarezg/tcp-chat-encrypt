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

type keys struct {
	privateKey []byte
	publicKey  []byte
}

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
			log.Fatal(err)
		}

		go handleRequest(conn)
	}
}

// handleRequest Handle client request
//  @param1 (conn): connection between client and server
func handleRequest(conn net.Conn) {
	defer conn.Close()

	mess := " - Welcome to chat - \nEnter your name: "

	// write message
	_, err := conn.Write([]byte(mess))
	if err != nil {
		log.Fatal(err)
	}

	reply := make([]byte, lenBuff)

	// read user name
	res := bufio.NewReader(conn)

	number, err := res.Read(reply)
	if err != nil {
		log.Fatal(err)
	}

	// check number of connected users
	if len(conns) > 1 {
		_, err = conn.Write([]byte("Chat full, try again later\n"))
		if err != nil {
			log.Fatal(err)
		}

		return
	}

	name := reply[:number-1]

	conns = append(conns, conn)

	// generate keys
	var (
		user1 keys
		user2 keys
	)

	if len(conns) == limitConn {
		// keys user1
		auxPrivateKey, err := rsa.GenerateKey(rand.Reader, lenBuff)
		if err != nil {
			log.Fatal(err)
		}

		user1.privateKey = x509.MarshalPKCS1PrivateKey(auxPrivateKey)
		auxPublicKey := &auxPrivateKey.PublicKey
		user1.publicKey = x509.MarshalPKCS1PublicKey(auxPublicKey)

		// keys user2
		auxPrivateKey, err = rsa.GenerateKey(rand.Reader, lenBuff)
		if err != nil {
			log.Fatal(err)
		}

		user2.privateKey = x509.MarshalPKCS1PrivateKey(auxPrivateKey)
		auxPublicKey = &auxPrivateKey.PublicKey
		user2.publicKey = x509.MarshalPKCS1PublicKey(auxPublicKey)
	}

	fmt.Printf("%s connected\n", name)

	mess = fmt.Sprintf(" - %s connected - \n", name)
	mess += fmt.Sprintf(" - %d connected users - \n", len(conns))

	// write message to all connections
	for _, element := range conns {
		_, err = element.Write([]byte(mess))
		if err != nil {
			log.Fatal(err)
		}

		var (
			pubK  []byte
			privK []byte
		)

		if len(conns) == limitConn {
			if element == conn {
				pubK = user1.publicKey
				privK = user2.privateKey
			} else {
				pubK = user2.publicKey
				privK = user1.privateKey
			}

			messKey := fmt.Sprintf("Enter this code:\nPUBK-%x\n\n", pubK)
			messKey += fmt.Sprintf("Enter this code:\nPRIVK-%x\n\n", privK)

			_, err = element.Write([]byte(messKey))
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	for {
		reply = make([]byte, lenBuff)

		// read text to chat
		number, err = res.Read(reply)
		if err != nil || string(reply[:number-1]) == "EXIT" {
			if errors.Is(err, io.EOF) || string(reply[:number-1]) == "EXIT" {
				// remove connection from chat
				for n, element := range conns {
					if conn == element {
						conns = append(conns[:n], conns[n+1:]...)
					}

					mess = fmt.Sprintf(" - Bye %s - \n", name)

					_, err = element.Write([]byte(mess))
					if err != nil {
						log.Fatal(err)
					}
				}

				for _, element := range conns {
					mess = fmt.Sprintf(" - %d connected users - \n", len(conns))

					_, err = element.Write([]byte(mess))
					if err != nil {
						log.Fatal(err)
					}
				}

				fmt.Printf("%s offline\n", name)

				break
			}

			log.Fatal(err)
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
					log.Fatal(err)
				}
			}
		}
	}
}
