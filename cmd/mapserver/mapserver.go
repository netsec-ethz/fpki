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

	updateChan    chan struct{}
	updateErrChan chan error
}

func NewMapserver(ctx context.Context, config *Config) (*MapServer, error) {
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

		updateChan:    make(chan struct{}),
		updateErrChan: make(chan error),
	}

	// Start listening for update requests.
	go func() {
		// Non stop read from updateChan. Unless requested to exit.
		for {
			select {
			case <-s.updateChan:
				s.update()
			case <-ctx.Done():
				// Requested to exit.
				close(s.updateChan)
				return
			}
		}
	}()

	return s, nil
}

// Update triggers an update. If an ongoing update is still in process, it blocks.
func (s *MapServer) Update() error {
	// Signal we want an update.
	s.updateChan <- struct{}{}

	// Wait for the answer (in form of an error).
	err := <-s.updateErrChan
	return err
}

func (s *MapServer) update() {
	fmt.Printf("======== update started  at %s\n", time.Now().UTC().Format(time.RFC3339))
	time.Sleep(3 * time.Second)
	fmt.Printf("======== update finished at %s\n\n", time.Now().UTC().Format(time.RFC3339))

	// Queue answer in form of an error:
	err := error(nil)
	s.updateErrChan <- err
}

func (s *MapServer) Listen(ctx context.Context) error {
	<-ctx.Done()
	return nil
}
