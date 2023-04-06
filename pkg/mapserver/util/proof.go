package util

import (
	"bytes"
	"fmt"
	"strings"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/prover"
)

// CheckProof checks the validity of the proof. The CA from the certificate is checked for
// those subdomains where entries are found in the mapserver.
func CheckProof(
	proof []*mapCommon.MapServerResponse,
	name string,
	cert *ctx509.Certificate,
) error {

	caName := cert.Issuer.String()
	foundPoP := false
	for i, proof := range proof {
		if !strings.Contains(name, proof.Domain) {
			return fmt.Errorf("proof step %d of %s: subdomain %s not in name %s",
				i, name, proof.Domain, name)
		}
		proofType, correct, err := prover.VerifyProofByDomain(proof)
		if err != nil {
			return fmt.Errorf("proof step %d of %s: verifying proof: %w",
				i, name, err)
		}
		if !correct {
			return fmt.Errorf("proof step %d of %s: incorrect proof", i, name)
		}
		if proofType == mapCommon.PoP {
			foundPoP = true
			domainEntry, err := mapCommon.DeserializeDomainEntry(proof.DomainEntryBytes)
			if err != nil {
				return fmt.Errorf("proof step %d of %s: deserializing payload: %w",
					i, name, err)
			}
			// Find the CA entry that corresponds to the CA in this certificate.
			for _, ca := range domainEntry.Entries {
				if ca.CAName == caName {
					for _, raw := range ca.DomainCerts {
						if bytes.Equal(raw, cert.Raw) {
							return nil
						}
					}
				}
			}
		} else {
			if len(proof.DomainEntryBytes) != 0 {
				return fmt.Errorf("payload for a absence step (%s)", name)
			}
		}
	}
	return fmt.Errorf("certificate/CA not found; all proof steps are PoA? %v",
		!foundPoP)
}
