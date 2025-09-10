// Package main defines executable program that establishes predefined IPC method
// and invokes another program procedure through this IPC channel.
package main

import (
	"client-cli/internal/command"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

var (
	flagProfile string
)

const (
	// commandHashName defines expected CLI argument value to invoke hash command
	commandHashName = "hash"

	// commandSignName defines expected CLI argument value to invoke sign command
	commandSignName = "sign"
)

const (
	nArgsHash = 1
	nArgsSign = 3
)

// main defines executable program logic
func main() {
	flag.StringVar(&flagProfile, "profile", "Default", "Specify profile to used")
	flag.Parse()
	args := flag.Args()

	globalUsage := `Example CLI that interacts with Crypto Broker

Usage:
  client [flags] command_name [arguments...]

Available Commands:
  hash		Send hashing request to crypto broker
  sign		Send signing request to crypto broker`
	if len(args) < 1 {
		fmt.Println(globalUsage)
		
		os.Exit(0)
	}

	// Delay needs to be less than 10 seconds for Kubernetes not to restart the app
	toSleep, err := time.ParseDuration("5s")
	if err != nil {
		panic(err)
	}

	logger := log.New(os.Stdout, "CLIENT: ", log.Ldate|log.Lmicroseconds)

	switch args[0] {
	case commandHashName:
		usage := `Hash sends hashing request to crypto broker.

Example:
	client-cli --profile=Default hash "Hello world"

Arguments:
	1. Sequence of bytes that are meant to be hashed

Flags:
	--profile={PROFILE_NAME}`
		arguments := args[1:]
		if len(arguments) < nArgsHash {
			fmt.Println(usage)

			os.Exit(1)
		}

		commandHash := command.InitHash(logger)
		if err := commandHash.Run(context.Background(), []byte(arguments[0]), flagProfile, toSleep); err != nil {
			logger.Fatal(err) // os.Exit(1)
		}
	case commandSignName:
		usage := `Sign sends certificate signing request to crypto broker.

Example:
	client-cli --profile=Default sign ./certificate_signing_request.csr ./ca_cert.pem ./private_key.pem

Arguments:
	1. Relative OS path to certificate signing request file
	2. Relative OS path to CA certificate file
	3. Relative OS path to private key file

Flags:
	--profile={PROFILE_NAME}`
		arguments := args[1:]
		if len(arguments) < nArgsSign {
			fmt.Println(usage)

			os.Exit(1)
		}

		commandSign := command.InitSign(logger)
		if err := commandSign.Run(context.Background(), arguments[0], arguments[1], arguments[2], flagProfile, toSleep); err != nil {
			logger.Fatal(err) // os.Exit(1)
		}
	default:
		fmt.Println(globalUsage)

		os.Exit(1)
	}

	os.Exit(0)
}
