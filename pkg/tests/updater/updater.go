package updater

import (
	"context"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type CertsPoliciesOrBoth int

const (
	CertsOnly CertsPoliciesOrBoth = iota
	PoliciesOnly
	BothCertsAndPolicies
)

// UpdateDBwithRandomCerts creates in DB four certificates and two policies per domain in domains.
// The certificates correspond to two different certificate chains: the first chain is
// domainName->c1.com->c0.com , and the second chain is domainName->c0.com .
func UpdateDBwithRandomCerts(
	ctx context.Context,
	t tests.T,
	conn db.Conn,
	domains []string,
	certsOrPolicies []CertsPoliciesOrBoth,
) (
	// returns:
	certs []*ctx509.Certificate,
	policies []common.PolicyDocument,
	IDs []*common.SHA256Output,
	parentIDs []*common.SHA256Output,
	names [][]string,
) {

	// Prepare the return variables.
	certs = make([]*ctx509.Certificate, 0, 4*len(domains))
	IDs = make([]*common.SHA256Output, 0, len(certs))
	parentIDs = make([]*common.SHA256Output, 0, len(certs))
	names = make([][]string, 0, len(certs))
	policies = make([]common.PolicyDocument, 0, len(certs))

	// Generate and insert into DB the requested certificate hierarchies.
	for i, domain := range domains {
		var c []*ctx509.Certificate
		var certIDs, parentCertIDs []*common.SHA256Output
		var domainNames [][]string
		var pols []common.PolicyDocument

		// Generate random hierarchies depending of the selection.
		if certsOrPolicies[i] != PoliciesOnly {
			c, certIDs, parentCertIDs, domainNames = random.BuildTestRandomCertHierarchy(t, domain)
		}
		if certsOrPolicies[i] != CertsOnly {
			pols = random.BuildTestRandomPolicyHierarchy(t, domain)
		}

		// Insert all generated hierarchies into DB.
		err := updater.UpdateWithKeepExisting(ctx, conn, domainNames, certIDs, parentCertIDs,
			c, util.ExtractExpirations(c), pols)
		require.NoError(t, err)

		// Add to return variables.
		certs = append(certs, c...)
		IDs = append(IDs, certIDs...)
		parentIDs = append(parentIDs, parentCertIDs...)
		names = append(names, domainNames...)
		policies = append(policies, pols...)
	}

	// Coalescing of payloads.
	err := updater.CoalescePayloadsForDirtyDomains(ctx, conn)
	require.NoError(t, err)

	// Create/update the SMT.
	err = updater.UpdateSMT(ctx, conn)
	require.NoError(t, err)

	// And cleanup dirty, flagging the end of the update cycle.
	err = conn.CleanupDirty(ctx)
	require.NoError(t, err)

	return
}
