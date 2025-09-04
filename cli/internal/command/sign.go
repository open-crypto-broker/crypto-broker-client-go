package command

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	cryptobrokerclientgo "github.com/open-crypto-broker/crypto-broker-client-go"
)

type Sign struct {
	logger              *log.Logger
	cryptoBrokerLibrary *cryptobrokerclientgo.Library
}

// InitSign initializes sign command. This may panic in case of failure.
func InitSign(logger *log.Logger) *Sign {
	lib, err := cryptobrokerclientgo.NewLibrary()
	if err != nil {
		panic(err)
	}

	return &Sign{logger: logger, cryptoBrokerLibrary: lib}
}

// Run executes command logic.
func (command *Sign) Run(ctx context.Context, filePathCSR, filePathCACert, filePathSigningKey string, Profile string, delay time.Duration) error {
	defer command.gracefulShutdown()

	rawContentCSR, err := command.readFileBytes(filePathCSR)
	if err != nil {
		return fmt.Errorf("could not read certificate signing request file, err: %w", err)
	}

	rawContentCACert, err := command.readFileBytes(filePathCACert)
	if err != nil {
		return fmt.Errorf("could not read CA Certificate file, err: %w", err)
	}

	rawContentSigningKey, err := command.readFileBytes(filePathSigningKey)
	if err != nil {
		return fmt.Errorf("could not read signing key file, err: %w", err)
	}

	customSubject := pkix.Name{
		Country:      []string{"DE"},
		Province:     []string{"BA"},
		Organization: []string{"SAP"},
		CommonName:   "MyCert",
		SerialNumber: "01234556",
	}.String()

	payload := cryptobrokerclientgo.SignCertificatePayload{
		Profile:      Profile,
		CSR:          rawContentCSR,
		CAPrivateKey: rawContentSigningKey,
		CACert:       rawContentCACert,
		Subject:      &customSubject,
		Metadata: &cryptobrokerclientgo.Metadata{
			Id:        uuid.New().String(),
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		},
	}

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
				if err := command.signCertificate(ctx, payload); err != nil {
					return err
				}
			}
		}
	} else {
		if err := command.signCertificate(ctx, payload); err != nil {
			return err
		}
		return nil
	}
}

func (command *Sign) signCertificate(ctx context.Context, payload cryptobrokerclientgo.SignCertificatePayload) error {
	timestampSignStart := time.Now()
	responseBody, err := command.cryptoBrokerLibrary.SignCertificate(ctx, payload)
	if err != nil {
		return fmt.Errorf("failed to obtain signed certificate through CryptoBroker library, err: %w", err)
	}

	timestampSignFinish := time.Now()
	durationElapsedSign := timestampSignFinish.Sub(timestampSignStart)
	marshalledResp, err := json.MarshalIndent(responseBody, " ", "  ")
	if err != nil {
		return err
	}

	command.logger.Printf("Sign Response:\n%s", string(marshalledResp))
	command.logger.Printf("Certificate Signing took: %fµs\n", float64(durationElapsedSign.Nanoseconds())/1000.0)

	return nil
}

// gracefulShutdown closes library connection.
func (command *Sign) gracefulShutdown() error {
	command.logger.Printf("Closing crypto broker library connection\n")
	return command.cryptoBrokerLibrary.Close()
}

// readFileBytes opens a file and reads its bytes
func (command *Sign) readFileBytes(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s file, err: %w", filePath, err)
	}

	defer f.Close()

	rawContent, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not read %s file, err: %w", filePath, err)
	}

	return rawContent, nil
}
