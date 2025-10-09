package command

import (
	"context"
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
func InitSign(ctx context.Context, logger *log.Logger) *Sign {
	lib, err := cryptobrokerclientgo.NewLibrary(ctx)
	if err != nil {
		panic(err)
	}

	return &Sign{logger: logger, cryptoBrokerLibrary: lib}
}

// Run executes command logic.
func (command *Sign) Run(ctx context.Context, filePathCSR, filePathCACert, filePathSigningKey, flagProfile, flagEncoding, flagSubject string, flagLoop int64) error {
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

	var subject *string
	if flagSubject != "" {
		subject = &flagSubject
	} else {
		subject = nil
	}

	payload := cryptobrokerclientgo.SignCertificatePayload{
		Profile:      flagProfile,
		CSR:          rawContentCSR,
		CAPrivateKey: rawContentSigningKey,
		CACert:       rawContentCACert,
		Subject:      subject,
		Metadata: &cryptobrokerclientgo.Metadata{
			Id:        uuid.New().String(),
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		},
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	if flagLoop >= 0 && flagLoop <= 1000 {
		toSleep, err := time.ParseDuration(fmt.Sprintf("%dms", flagLoop))
		if err != nil {
			panic(err)
		}

		for {
			select {
			case <-c:
				command.logger.Printf("Received SIGTERM singal\n")
				return nil
			default:
				time.Sleep(toSleep)
				
				if err := command.signCertificate(ctx, payload, flagEncoding); err != nil {
					return err
				}
			}
		}
	} else {
		if err := command.signCertificate(ctx, payload, flagEncoding); err != nil {
			return err
		}
		return nil
	}
}

func (command *Sign) signCertificate(ctx context.Context, payload cryptobrokerclientgo.SignCertificatePayload, flagEncoding string) error {
	timestampSignStart := time.Now()
	encodingOpt := cryptobrokerclientgo.WithPEMEncoding()
	if strings.ToLower(flagEncoding) == "b64" {
		encodingOpt = cryptobrokerclientgo.WithBase64Encoding()
	}
	
	responseBody, err := command.cryptoBrokerLibrary.SignCertificate(ctx, payload, encodingOpt)
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
