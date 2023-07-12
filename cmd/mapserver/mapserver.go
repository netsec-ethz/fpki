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
}

func NewMapserver(config *Config) (*MapServer, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

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
	return &MapServer{
		Updater:   updater,
		Responder: resp,
		Cert:      cert,
		Key:       key,
	}, nil
}

func (s *MapServer) Update() error {
	fmt.Printf("======== update started  at %s\n", time.Now().UTC().Format(time.RFC3339))
	time.Sleep(3 * time.Second)
	fmt.Printf("======== update finished at %s\n", time.Now().UTC().Format(time.RFC3339))
	return nil
}

func (s *MapServer) Listen(ctx context.Context) error {
	<-ctx.Done()
	return nil
}
