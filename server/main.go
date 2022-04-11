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

const (
	lenBuff   = 1024
	args      = 2
	limitConn = 2
)

// user connection structure.
type connUser struct {
	name string   // name
	conn net.Conn // connection
}

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

	var conns []connUser
	pConns := &conns

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Print(err)

			return
		}

		go handleRequest(conn, pConns)
	}
}

// handleRequest Handle client request
//  @param1 (conn): connection between client and server
//  @param2 (pConns): connections pointer
func handleRequest(conn net.Conn, pConns *[]connUser) {
	defer conn.Close()

	reply := make([]byte, lenBuff)

	// write message
	_, err := conn.Write([]byte(" - Welcome to chat - \nEnter your name: "))
	if err != nil {
		log.Print(err)

		return
	}

	// read user name
	number, err := bufio.NewReader(conn).Read(reply)
	if err != nil {
		log.Print(err)

		return
	}

	// check number of connected users
	if len(*pConns) > limitConn-1 {
		_, err = conn.Write([]byte("ERROR: Chat full, try again later\n"))
		if err != nil {
			return
		}

		return
	}

	name := reply[:number-1]
	user := connUser{name: string(name), conn: conn}

	// append connection
	*pConns = append(*pConns, user)

	fmt.Println(user.name, "connected")

	// write message to all connections
	err = writeAllConns(*pConns, user)
	if err != nil {
		return
	}

	for {
		err = readAndWriteOnConn(*pConns, user)
		if err != nil {
			log.Print(err)

			break
		}
	}
}

// readAndWriteOnConn Read and write on connection
//  @param1 (conns): connection slice
//  @param2 (user): structure variable user
//
//  @return1 (err): error variable
func readAndWriteOnConn(conns []connUser, user connUser) (err error) {
	reply := make([]byte, lenBuff)

	// read text to chat
	number, err := bufio.NewReader(user.conn).Read(reply)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			return
		}

		// remove connection from chat
		err = deleteConn(conns, user)
		if err != nil {
			return
		}

		fmt.Println(user.name, "offline")

		return
	}

	// write message to all connections
	err = writeAllExceptCurrentConn(conns, user, reply[:number])
	if err != nil {
		return
	}

	return
}

// deleteConn Delete connection from server
//  @param1 (conns): connection slice
//  @param2 (user): structure variable user
//
//  @return1 (err): error variable
func deleteConn(conns []connUser, user connUser) (err error) {
	for n, element := range conns {
		if user.conn == element.conn {
			conns = append(conns[:n], conns[n+1:]...)
		}

		_, err = element.conn.Write([]byte(fmt.Sprintf(" - Bye %s - \n", user.name)))
		if err != nil {
			return
		}
	}

	return
}

// writeAllExceptCurrentConn Write to all except the current connection
//  @param1 (conns): connection slice
//  @param2 (user): structure variable user
//  @param3 (mess): message to write
//
//  @return1 (err): error variable
func writeAllExceptCurrentConn(conns []connUser, user connUser, mess []byte) (err error) {
	if string(mess) == "\n" {
		return
	}

	for _, element := range conns {
		if element.conn != user.conn {
			// check prefix, to not apply formatting
			if strings.HasPrefix(string(mess), "PUBK-") {
				_, err = element.conn.Write(mess)
				if err != nil {
					return
				}

				continue
			}

			_, err = element.conn.Write([]byte(fmt.Sprintf(
				"%s (%s): %s",
				user.name,
				time.Now().Format(time.RFC822Z),
				mess),
			))
			if err != nil {
				return
			}
		}
	}

	return
}

// writeAllConns Write to all connections
//  @param1 (conns): connection slice
//  @param2 (user): structure variable user
//
//  @return1 (err): error variable
func writeAllConns(conns []connUser, user connUser) (err error) {
	for _, element := range conns {
		_, err = element.conn.Write([]byte(fmt.Sprintf(" - %s connected - \n", user.name)))
		if err != nil {
			log.Print(err)

			return
		}

		if len(conns) == limitConn {
			_, err = element.conn.Write([]byte(" - NOTICE: start secure chat - \n"))
			if err != nil {
				log.Print(err)

				return
			}
		}
	}

	return
}
