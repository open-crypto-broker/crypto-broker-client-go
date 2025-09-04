package command

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	cryptobrokerclientgo "github.com/open-crypto-broker/crypto-broker-client-go"
)

// Hash represents command that repeatily sends hash request to crypto broker and displays its response
type Hash struct {
	logger              *log.Logger
	cryptoBrokerLibrary *cryptobrokerclientgo.Library
}

// InitHash initializes hash command. This may panic in case of failure.
func InitHash(logger *log.Logger) *Hash {
	lib, err := cryptobrokerclientgo.NewLibrary()
	if err != nil {
		panic(err)
	}

	return &Hash{logger: logger, cryptoBrokerLibrary: lib}
}

// Run executes command logic.
func (command *Hash) Run(ctx context.Context, Input []byte, Profile string, delay time.Duration) error {
	defer command.gracefulShutdown()

	payload := cryptobrokerclientgo.HashDataPayload{
		Input:   Input,
		Profile: Profile,
		Metadata: &cryptobrokerclientgo.Metadata{
			Id:        uuid.New().String(),
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		},
	}

	command.logger.Printf("Hashing %s using %s profile \n", string(Input), Profile)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	isDeployed := os.Getenv("DOCKER_DEPLOYED")
	if strings.ToLower(isDeployed) == "true" {
		for {
			select {
			case <-c:
				command.logger.Printf("Received SIGTERM singal\n")
				return nil
			default:
				time.Sleep(delay)
				if err := command.hashBytes(ctx, payload); err != nil {
					return err
				}
			}
		}
	} else {
		if err := command.hashBytes(ctx, payload); err != nil {
			return err
		}
		return nil
	}
}

// hashBytes sends hash request through crypto broker library.
// In case of success it displays response and returns nil error, otherwise it returns non-nil error.
// Internally method measures execution time and prints it through logger.
func (command *Hash) hashBytes(ctx context.Context, payload cryptobrokerclientgo.HashDataPayload) error {
	timestampHashingStart := time.Now()
	responseBody, err := command.cryptoBrokerLibrary.HashData(ctx, payload)
	if err != nil {
		return err
	}

	timestampHashingFinish := time.Now()
	durationElapsedHashing := timestampHashingFinish.Sub(timestampHashingStart)
	marshalledResp, err := json.MarshalIndent(responseBody, " ", "  ")
	if err != nil {
		return err
	}

	command.logger.Println("Hashed response:\n", string(marshalledResp))
	command.logger.Printf("Data Hashing took: %fµs\n", float64(durationElapsedHashing.Nanoseconds())/1000.0)

	return nil
}

// gracefulShutdown closes library connection.
func (command *Hash) gracefulShutdown() error {
	command.logger.Printf("Closing crypto broker library connection\n")
	return command.cryptoBrokerLibrary.Close()
}
