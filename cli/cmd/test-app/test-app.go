// Package main defines executable program that establishes predefined IPC method
// and invokes another program procedure through this IPC channel.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"test-app/internal/command"
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

	if len(args) < 1 {
		fmt.Println(`Simple CLI that knows how to work with crypto broker. It has few commands.

Usage:
  client [flags] command_name [arguments...]

Available Commands:
  hash		Runs logic that periodicaly sends hashing request to crypto broker
  sign		Runs logic that periodically requests a CSR. It requires paths to: csr, ca-cert, singing key as arguments`)
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
		arguments := args[1:]
		if len(arguments) < nArgsHash {
			logger.Fatalf("Please provide exactly %d argument(s) to command", nArgsHash)
		}

		commandHash := command.InitHash(logger)
		if err := commandHash.Run(context.Background(), []byte(arguments[0]), flagProfile, toSleep); err != nil {
			logger.Fatal(err) // os.Exit(1)
		}
	case commandSignName:
		arguments := args[1:]
		if len(arguments) < nArgsSign {
			logger.Fatalf("Please provide exactly %d argument(s) to command", nArgsSign)
		}

		commandSign := command.InitSign(logger)
		if err := commandSign.Run(context.Background(), arguments[0], arguments[1], arguments[2], flagProfile, toSleep); err != nil {
			logger.Fatal(err) // os.Exit(1)
		}
	default:
		logger.Fatalf("Invalid argument value, got %s .  Valid arguments: '%s' or '%s'", args[0], commandHashName, commandSignName)
	}

	os.Exit(0)
}
