package mapserver

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/config"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/util"
)

const APIPort = 8443 // TODO: should be a config parameter

type MapServer struct {
	Updater   *updater.MapUpdater
	Responder *responder.MapResponder
	Conn      db.Conn
	// Crypto material of this map server.
	Cert *ctx509.Certificate
	Key  *rsa.PrivateKey
	TLS  *tls.Certificate

	updateChan    chan context.Context
	updateErrChan chan error
}

func NewMapServer(ctx context.Context, conf *config.Config) (*MapServer, error) {
	// Load cert and key.
	pemCert, err := ioutil.ReadFile(conf.CertificatePemFile)
	if err != nil {
		return nil, fmt.Errorf("error loading certificate: %w", err)
	}
	cert, err := util.CertificateFromPEMBytes(pemCert)
	if err != nil {
		return nil, fmt.Errorf("error loading certificate: %w", err)
	}
	pemKey, err := ioutil.ReadFile(conf.PrivateKeyPemFile)
	if err != nil {
		return nil, fmt.Errorf("error loading private key: %w", err)
	}
	key, err := util.RSAKeyFromPEM(pemKey)
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

	// Create the TLS configuration for the HTTPS API server.
	// TODO(juagargi) we probably want to use a different certifiate to serve HTTPS.
	tlsCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return nil, fmt.Errorf("error loading cert/key for TLS: %w", err)
	}

	// Connect to the DB.
	conn, err := mysql.Connect(conf.DBConfig)
	if err != nil {
		return nil, fmt.Errorf("error connecting to the DB: %w", err)
	}

	// Create map updater.
	updater, err := updater.NewMapUpdater(conf.DBConfig, conf.CTLogServerURLs)
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
		Conn:      conn,
		Cert:      cert,
		Key:       key,
		TLS:       &tlsCert,

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
	http.HandleFunc("/getproof", s.apiGetProof)
	http.HandleFunc("/getpayloads", s.apiGetPayloads)

	server := &http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*s.TLS},
		},
	}
	var errListen error
	go func() {
		errListen = server.ListenAndServeTLS("", "")
	}()
	<-ctx.Done()

	if errListen != nil {
		return fmt.Errorf("error serving API: %w", errListen)
	}
	//Shutdown the server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("error shutting down API server: %w", err)
	}
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

// apiGetProof expects one GET parameter "domain" with a string value for the domain name.
// It returns a json formatted structure with
func (s *MapServer) apiGetProof(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	ctx, cancelF := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancelF()
	proofChain, err := s.Responder.GetProof(ctx, domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("obtaining proof: %s", err), http.StatusBadRequest)
		return
	}
	enc := json.NewEncoder(w)
	err = enc.Encode(proofChain)
	if err != nil {
		http.Error(w, fmt.Sprintf("encoding proof: %s", err), http.StatusInternalServerError)
		return
	}
}

// apiGetPaylpads expects one GET parameer "ids" with a string value of the hex representation
// of all requested IDs.
// Since each ID is 32 bytes, the hex string will always be a multiple of 64.
func (s *MapServer) apiGetPayloads(w http.ResponseWriter, r *http.Request) {
	ctx, cancelF := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancelF()

	hexIDs := r.URL.Query().Get("ids")
	if len(hexIDs)%(common.SHA256Size*2) != 0 {
		http.Error(w, "parameter \"ids\" length is not a concatenation of 32 char IDs",
			http.StatusBadRequest)
		return
	}
	ids := make([]*common.SHA256Output, len(hexIDs)/common.SHA256Size/2)
	for i := 0; i < len(ids); i++ {
		h := hexIDs[i*common.SHA256Size*2 : (i+1)*common.SHA256Size*2]
		id, err := hex.DecodeString(h)
		if err != nil {
			http.Error(w, fmt.Sprintf("not a hexadecimal ID: %s", h), http.StatusBadRequest)
			return
		}
		ids[i] = (*common.SHA256Output)(id)
	}

	// Obtain the payloads.
	payloads, err := s.Conn.RetrieveCertificatePayloads(ctx, ids)
	if err != nil {
		http.Error(w, fmt.Sprintf("error obtaining payloads for %s\nError is: %s",
			hexIDs, err), http.StatusBadRequest)
		return
	}
	enc := json.NewEncoder(w)
	err = enc.Encode(payloads)
	if err != nil {
		http.Error(w, fmt.Sprintf("encoding proof: %s", err), http.StatusInternalServerError)
		return
	}
}

func (s *MapServer) pruneAndUpdate(ctx context.Context) {
	// prune() and update() both send an answer to the updateErrChan. Refrain from updating if
	// pruning failed.
	s.prune(ctx)
	err := <-s.updateErrChan
	if err != nil {
		s.updateErrChan <- err
		return
	}

	// update() will send its own response to the updateErrChan.
	s.update(ctx)
}

// prune only removes the affected certificates from the certs table and adds the affected domains
// to the dirty table. Because update is always called right after prune, we don't need to first
// compute the coalesced domains for those dirty domains after prune and before update. It is
// sufficient to call CoalescePayloadsForDirtyDomains after update and it will take care of all
// dirty domains, coming from both prune and update.
func (s *MapServer) prune(ctx context.Context) {
	fmt.Printf("======== prune started  at %s\n", getTime())
	defer fmt.Printf("======== prune finished at %s\n\n", getTime())

	err := s.Updater.Conn.PruneCerts(ctx, time.Now())
	if err != nil {
		s.updateErrChan <- fmt.Errorf("pruning: %w", err)
	}

	s.updateErrChan <- error(nil) // Always answer something.
}

func (s *MapServer) update(ctx context.Context) {
	fmt.Printf("======== update started  at %s\n", getTime())
	defer fmt.Printf("======== update finished at %s\n\n", getTime())

	if err := s.updateCerts(ctx); err != nil {
		s.updateErrChan <- err
		return
	}
	// TODO(juagargi) do policy certificates here.

	fmt.Printf("coalescing certificate payloads at %s\n", getTime())
	if err := s.Updater.CoalescePayloadsForDirtyDomains(ctx); err != nil {
		s.updateErrChan <- err
		return
	}

	// Update SMT.
	fmt.Printf("updating SMT at %s\n", getTime())
	if err := s.Updater.UpdateSMT(ctx); err != nil {
		s.updateErrChan <- fmt.Errorf("updating SMT: %w", err)
		return
	}

	// Cleanup.
	fmt.Printf("cleaning up at %s\n", getTime())
	if err := s.Updater.Conn.CleanupDirty(ctx); err != nil {
		s.updateErrChan <- fmt.Errorf("cleaning up DB: %w", err)
		return
	}

	// Always queue answer in form of an error:
	s.updateErrChan <- error(nil)
}

func (s *MapServer) updateCerts(ctx context.Context) error {
	if err := s.Updater.StartFetchingRemaining(); err != nil {
		return fmt.Errorf("retrieving start and end indices: %w", err)
	}
	defer s.Updater.StopFetching()

	// Main update loop.
	for s.Updater.NextBatch(ctx) {
		n, err := s.Updater.UpdateNextBatch(ctx)

		fmt.Printf("updated %5d certs batch at %s\n", n, getTime())
		if err != nil {
			// We stop the loop here, as probably requires manual inspection of the logs, etc.
			return fmt.Errorf("updating next batch of x509 certificates: %w", err)
		}
	}
	return nil
}

func getTime() string {
	return time.Now().UTC().Format(time.RFC3339)
}
