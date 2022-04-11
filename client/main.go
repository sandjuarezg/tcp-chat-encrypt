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

const (
	args     = 2
	msgParts = 2
	lenBuff  = 1064
)

var errLimit = errors.New("ERROR: Chat full, try again later")

func main() {
	if len(os.Args) != args {
		log.Fatal("Invalid input: [port]")
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%s", os.Args[1]))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	var (
		privKey      *rsa.PrivateKey
		pubKeyFriend *rsa.PublicKey
		wait         sync.WaitGroup
	)

	wait = sync.WaitGroup{}

	wait.Add(1)

	go func(wait *sync.WaitGroup) {
		defer wait.Done()

		// write on connection
		for {
			err = writeOnConn(conn, pubKeyFriend)
			if err != nil {
				log.Fatal(err)
			}
		}
	}(&wait)

	// read from connection
	for {
		err = readFromConn(conn, privKey, pubKeyFriend)
		if err != nil {
			log.Print(err)

			break
		}
	}

	wait.Wait()
}

// readFromConn Read message from conn
//  @param1 (conn): connection
//  @param2 (privKey): private key
//  @param3 (pubKeyFriend): friend public key
//
//  @return1 (err): error variable
func readFromConn(conn net.Conn, privKey *rsa.PrivateKey, pubKeyFriend *rsa.PublicKey) (err error) {
	reply := make([]byte, lenBuff)

	number, err := conn.Read(reply)
	if err != nil {
		if errors.Is(err, io.EOF) {
			os.Exit(0)
		}

		return
	}

	// check possible error message
	if strings.HasPrefix(string(reply[:number]), "ERROR") {
		err = errLimit

		return
	}

	// check 2 users connected
	if strings.Contains(string(reply[:number]), "NOTICE") {
		// generate private key
		privKey, err = rsa.GenerateKey(rand.Reader, lenBuff)
		if err != nil {
			return
		}

		mess := fmt.Sprintf("PUBK-%x", x509.MarshalPKCS1PublicKey(&privKey.PublicKey))

		_, err = conn.Write([]byte(mess))
		if err != nil {
			return
		}

		fmt.Print(string(reply[:number]))

		return
	}

	// check if key was received
	if strings.HasPrefix(string(reply[:number]), "PUBK-") {
		auxPubKey := strings.TrimPrefix(string(reply[:number]), "PUBK-")

		dst := make([]byte, hex.DecodedLen(len(auxPubKey)))

		number, err = hex.Decode(dst, []byte(auxPubKey))
		if err != nil {
			return
		}

		pubKeyFriend, err = x509.ParsePKCS1PublicKey(dst[:number])
		if err != nil {
			return
		}

		return
	}

	if pubKeyFriend == nil {
		fmt.Print(string(reply[:number]))

		return
	}

	format, text := getFormatAndTextFromMessage(reply[:number])

	decrypt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, text, nil)
	if err != nil {
		return
	}

	// show message security
	fmt.Printf("%s: %s", format, decrypt)

	return
}

// writeOnConn Write message on conn
//  @param1 (conn): connection
//  @param2 (pubKeyFriend): friend public key
//
//  @return1 (err): error variable
func writeOnConn(conn net.Conn, pubKeyFriend *rsa.PublicKey) (err error) {
	var (
		reply   = make([]byte, lenBuff)
		message []byte
	)

	number, err := bufio.NewReader(os.Stdin).Read(reply)
	if err != nil {
		return
	}

	message = reply[:number]

	if pubKeyFriend != nil {
		message, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKeyFriend, reply[:number], nil)
		if err != nil {
			return
		}
	}

	_, err = conn.Write(message)
	if err != nil {
		return
	}

	return
}

// getFormatAndTextFromMessage Get separate message format and text
//  @param1 (mess): message
//
//  @return1 (format): part of the message format
//  @return2 (text): part of the message text
func getFormatAndTextFromMessage(mess []byte) (format, text []byte) {
	messSlice := bytes.Split(mess, []byte(": "))

	if len(messSlice) == msgParts {
		format = messSlice[0]
		text = messSlice[1]
	}

	return
}
