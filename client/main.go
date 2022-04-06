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
	"strings"
	"sync"
)

const args = 2
const msgParts = 2
const lenBuff = 1064

var (
	privateKey      *rsa.PrivateKey
	publicKeyFriend *rsa.PublicKey
)

func main() {
	if len(os.Args) != args {
		log.Fatal("Insufficient arguments: [port]")
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%s", os.Args[1]))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// read server message
	reply := make([]byte, lenBuff)

	_, err = conn.Read(reply)
	if err != nil {
		log.Print(err)

		return
	}

	fmt.Print(string(reply))

	// read name
	number, err := bufio.NewReader(os.Stdin).Read(reply)
	if err != nil {
		log.Print(err)

		return
	}

	// write name on connection
	_, err = conn.Write(reply[:number])
	if err != nil {
		log.Print(err)

		return
	}

	// read server messages
	number, err = conn.Read(reply)
	if err != nil {
		log.Print(err)

		return
	}

	// check possible error message
	if strings.HasPrefix(string(reply[:number]), "ERROR") {
		log.Print(string(reply[:number]))

		return
	}

	fmt.Print(string(reply[:number]))

	fmt.Println()
	fmt.Println(" - To activate secure chat, send this key to your friend- ")

	// generate private key
	privateKey, err = rsa.GenerateKey(rand.Reader, lenBuff)
	if err != nil {
		log.Print(err)

		return
	}

	// print public key
	fmt.Printf("PUBK-%x\n\n", x509.MarshalPKCS1PublicKey(&privateKey.PublicKey))

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

// readFromConn Read message from conn
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

	// check if key was received
	if strings.Contains(string(reply[:number]), "PUBK-") {
		_, text := getFormatAndTextFromMessage(reply[:number-1])

		auxPubKey := strings.TrimPrefix(string(text), "PUBK-")

		dst := make([]byte, hex.DecodedLen(len(auxPubKey)))

		number, err = hex.Decode(dst, []byte(auxPubKey))
		if err != nil {
			return
		}

		publicKeyFriend, err = x509.ParsePKCS1PublicKey(dst[:number])
		if err != nil {
			return
		}

		fmt.Println(" - Your friend has sent his key - ")

		return
	}

	// no key, show message without security
	if publicKeyFriend == nil {
		fmt.Print(string(reply[:number]))

		return
	}

	format, text := getFormatAndTextFromMessage(reply[:number])

	decrypt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, text, nil)
	if err != nil {
		return
	}

	// show message security
	fmt.Printf("(s)-%s: %s", format, decrypt)

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

	// check if key was written
	if strings.Contains(string(reply)[:number], "PUBK-") || publicKeyFriend == nil {
		_, err = conn.Write(reply[:number])
		if err != nil {
			return
		}

		return
	}

	encrypt, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKeyFriend, reply[:number], nil)
	if err != nil {
		return
	}

	_, err = conn.Write(encrypt)
	if err != nil {
		return
	}

	return
}

// getFormatAndTextFromMessage Get separate message format and text
//  @param1 (mess): message
//
//  @return1 (format): part of the message format
//  @return1 (text): part of the message text
func getFormatAndTextFromMessage(mess []byte) (format, text []byte) {
	messSlice := bytes.Split(mess, []byte(": "))

	if len(messSlice) == msgParts {
		format = messSlice[0]
		text = messSlice[1]
	}

	return
}
