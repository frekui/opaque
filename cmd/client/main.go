// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/frekui/opaque"
	"github.com/frekui/opaque/internal/pkg/util"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s is a simple example client of the opaque package. It can be used together with cmd/server.\nUsage:\n", os.Args[0])
		flag.PrintDefaults()
	}

	addr := flag.String("conn", "localhost:9999", "Host to connect to.")
	pwreg := flag.Bool("pwreg", false, "Register password.")
	auth := flag.Bool("auth", false, "Authenticate and send message to server")
	username := flag.String("username", "", "Username")
	password := flag.String("password", "", "Password")
	flag.Parse()
	if !*pwreg && !*auth {
		fmt.Fprintf(os.Stderr, "Exactly one of -pwreg and -auth must be given.\n")
		flag.Usage()
		os.Exit(1)
	}
	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	if *pwreg {
		err := util.Write(w, []byte("pwreg"))
		if err == nil {
			err = doPwreg(r, w, *username, *password)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "pwreg: %s\n", err)
			os.Exit(1)
		}
	} else {
		err := util.Write(w, []byte("auth"))
		if err == nil {
			err = doAuth(r, w, *username, *password, "Hello from client")
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "auth: %s\n", err)
			os.Exit(1)
		}
	}
}

func doPwreg(r *bufio.Reader, w *bufio.Writer, username, password string) error {
	sess, msg1, err := opaque.PwRegInit(username, password, 512)
	if err != nil {
		return err
	}
	data1, err := json.Marshal(msg1)
	if err != nil {
		return err
	}
	if err := util.Write(w, data1); err != nil {
		return err
	}

	data2, err := util.Read(r)
	if err != nil {
		return err
	}
	var msg2 opaque.PwRegMsg2
	if err := json.Unmarshal(data2, &msg2); err != nil {
		return err
	}

	msg3, err := opaque.PwReg2(sess, msg2)
	if err != nil {
		return err
	}
	data3, err := json.Marshal(msg3)
	if err != nil {
		return err
	}
	if err := util.Write(w, data3); err != nil {
		return err
	}

	final, err := util.Read(r)
	if err != nil {
		return err
	}
	if string(final) != "ok" {
		return fmt.Errorf("expected final ok, got %s", string(final))
	}

	return nil
}

func doAuth(r *bufio.Reader, w *bufio.Writer, username, password, msg string) error {
	sess, msg1, err := opaque.AuthInit(username, password)
	if err != nil {
		return err
	}
	data1, err := json.Marshal(msg1)
	if err != nil {
		return err
	}
	if err := util.Write(w, data1); err != nil {
		return err
	}

	data2, err := util.Read(r)
	if err != nil {
		return err
	}
	var msg2 opaque.AuthMsg2
	if err := json.Unmarshal(data2, &msg2); err != nil {
		return err
	}

	sharedSecret, msg3, err := opaque.Auth2(sess, msg2)
	if err != nil {
		return err
	}
	data3, err := json.Marshal(msg3)
	if err != nil {
		return err
	}
	if err := util.Write(w, data3); err != nil {
		return err
	}

	ok, err := util.Read(r)
	if err != nil {
		return err
	}
	if string(ok) != "ok" {
		return fmt.Errorf("Expected ok, got '%s'", string(ok))
	}

	// FIXME: Use a PRF to have separate keys for client->server and
	// server->client.
	key := sharedSecret[:16]
	plaintext, err := util.ReadAndDecrypt(r, key)
	if err != nil {
		return err
	}
	fmt.Printf("Received '%s'\n", plaintext)
	toServer := "Hi server!"
	fmt.Printf("Sending '%s'\n", toServer)
	if err := util.EncryptAndWrite(w, key, toServer); err != nil {
		return err
	}
	return nil
}
