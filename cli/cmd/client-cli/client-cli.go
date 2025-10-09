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
)

var (
	flagProfile string
	flagHelp bool
	flagEncoding string
	flagSubject string
	flagLoop int64
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
	flag.StringVar(&flagProfile, "profile", "Default", "Specify profile to be used")
	flag.StringVar(&flagEncoding, "encoding", "PEM", "Specify encoding to be used")
	flag.StringVar(&flagSubject, "subject", "", "Specify subject to be used for certificate generation")
	flag.Int64Var(&flagLoop, "loop", -1, "Specify delay for loop in miliseconds" )
	flag.BoolVar(&flagHelp, "h", false, "Displays CLI usage string")
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

	if flagHelp {
		fmt.Println(globalUsage)

		os.Exit(0)
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

		commandHash := command.InitHash(context.Background(), logger)
		if err := commandHash.Run(context.Background(), []byte(arguments[0]), flagProfile, flagLoop); err != nil {
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
	--profile={PROFILE_NAME}
	--encoding={PEM|B64}
	--subject={SUBJECT}`
		arguments := args[1:]
		if len(arguments) < nArgsSign {
			fmt.Println(usage)

			os.Exit(1)
		}

		commandSign := command.InitSign(context.Background(), logger)
		if err := commandSign.Run(context.Background(),
		 arguments[0], arguments[1], arguments[2], flagProfile, flagEncoding, flagSubject, flagLoop); err != nil {
			logger.Fatal(err) // os.Exit(1)
		}
	default:
		fmt.Println(globalUsage)

		os.Exit(1)
	}

	os.Exit(0)
}
