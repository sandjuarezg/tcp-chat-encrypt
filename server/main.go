package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
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

	fmt.Println("Listening on", listen.Addr())

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

	// check number of connected users
	if len(conns) > limitConn-1 {
		_, err = conn.Write([]byte("ERROR: Chat full, try again later\n"))
		if err != nil {
			log.Print(err)

			return
		}

		return
	}

	name := reply[:number-1]

	// append connection
	conns = append(conns, conn)

	fmt.Println(string(name), "connected")

	// write message to all connections
	for _, element := range conns {
		_, err = element.Write([]byte(fmt.Sprintf(" - %s connected - \n", name)))
		if err != nil {
			log.Print(err)

			return
		}

		if len(conns) == limitConn {
			_, err = element.Write([]byte(" - NOTICE: start secure chat - \n"))
			if err != nil {
				log.Print(err)

				return
			}
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
				// check prefix, to not apply formatting
				if strings.HasPrefix(string(reply[:number]), "PUBK-") {
					_, err = element.Write(reply[:number])
					if err != nil {
						log.Print(err)

						return
					}

					continue
				}

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
