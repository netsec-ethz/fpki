package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type MapServer struct {
	Updater   *updater.MapUpdater
	Responder *responder.MapResponder
	// Crypto material of this map server.
	Cert *ctx509.Certificate
	Key  *rsa.PrivateKey

	updateChan    chan context.Context
	updateErrChan chan error
}

func NewMapServer(ctx context.Context, config *Config) (*MapServer, error) {
	// Load cert and key.
	cert, err := util.CertificateFromPEMFile(config.CertificatePemFile)
	if err != nil {
		return nil, fmt.Errorf("error loading certificate: %w", err)
	}
	key, err := util.RSAKeyFromPEMFile(config.PrivateKeyPemFile)
	if err != nil {
		return nil, fmt.Errorf("error loading private key: %w", err)
	}

	// Check they correspond to one another.
	derBytes, err := util.RSAPublicToDERBytes(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("error encoding key to DER: %w", err)
	}
	if !bytes.Equal(derBytes, cert.RawSubjectPublicKeyInfo) {
		return nil, fmt.Errorf("certificate has different public key than key file")
	}

	// Connect to the DB.
	conn, err := mysql.Connect(config.DBConfig)
	if err != nil {
		return nil, fmt.Errorf("error connecting to the DB: %w", err)
	}

	// Create map updater.
	updater, err := updater.NewMapUpdater(config.DBConfig, config.CTLogServerURL)
	if err != nil {
		return nil, fmt.Errorf("error creating new map updater: %w", err)
	}

	// Create map responder.
	resp, err := responder.NewMapResponder(ctx, conn, key)
	if err != nil {
		return nil, fmt.Errorf("error creating new map responder: %w", err)
	}

	// Compose MapServer.
	s := &MapServer{
		Updater:   updater,
		Responder: resp,
		Cert:      cert,
		Key:       key,

		updateChan:    make(chan context.Context),
		updateErrChan: make(chan error),
	}

	// Start listening for update requests.
	go func() {
		// Non stop read from updateChan. Unless requested to exit.
		for {
			select {
			case c := <-s.updateChan:
				s.pruneAndUpdate(c)
			case <-ctx.Done():
				// Requested to exit.
				close(s.updateChan)
				return
			}
		}
	}()

	return s, nil
}

// Listen is responsible to start the listener for the responder.
func (s *MapServer) Listen(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// PruneAndUpdate triggers an update. If an ongoing update is still in process, it blocks.
func (s *MapServer) PruneAndUpdate(ctx context.Context) error {
	// Signal we want an update.
	s.updateChan <- ctx

	// Wait for the answer (in form of an error).
	err := <-s.updateErrChan
	return err
}

func (s *MapServer) pruneAndUpdate(ctx context.Context) {
	s.prune(ctx)
	s.update(ctx)
}

func (s *MapServer) prune(ctx context.Context) {
	getTime := func() string {
		return time.Now().UTC().Format(time.RFC3339)
	}
	fmt.Printf("======== prune started  at %s\n", getTime())
	// deleteme TODO
	fmt.Printf("======== prune finished at %s\n\n", getTime())
}

func (s *MapServer) update(ctx context.Context) {
	getTime := func() string {
		return time.Now().UTC().Format(time.RFC3339)
	}

	fmt.Printf("======== update started  at %s\n", getTime())
	if err := s.Updater.StartFetchingRemaining(); err != nil {

		s.updateErrChan <- fmt.Errorf("retrieving start and end indices: %w", err)
		return
	}

	// Main update loop.
	for s.Updater.NextBatch(ctx) {
		n, err := s.Updater.UpdateNextBatch(ctx)

		fmt.Printf("updated %5d certs batch at %s\n", n, getTime())
		if err != nil {
			// We stop the loop here, as probably requires manual inspection of the logs, etc.
			fmt.Printf("error: %s\n", err)
			break
		}
	}
	s.Updater.StopFetching()

	fmt.Printf("======== update finished at %s\n\n", getTime())

	// Queue answer in form of an error:
	s.updateErrChan <- error(nil)
}
