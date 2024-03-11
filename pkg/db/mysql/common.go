package mysql

import (
	"context"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// RetrievePolicyPayloads returns the payload for each certificate OR policy identified by the IDs
// parameter, in the same order (element i corresponds to IDs[i]).
func (c *mysqlDB) RetrieveCertificateOrPolicyPayloads(ctx context.Context, IDs []*common.SHA256Output,
) ([][]byte, error) {
	str := "SELECT policy_id,payload from policies WHERE policy_id IN " +
		repeatStmt(1, len(IDs)) +
		"UNION SELECT cert_id,payload from certs WHERE cert_id IN " +
		repeatStmt(1, len(IDs))
	params := make([]any, 2*len(IDs))
	for i, id := range IDs {
		params[i] = id[:]
		params[len(IDs)+i] = id[:]
	}
	rows, err := c.db.QueryContext(ctx, str, params...)
	if err != nil {
		return nil, err
	}

	m := make(map[common.SHA256Output][]byte, len(IDs))
	for rows.Next() {
		var id, payload []byte
		if err := rows.Scan(&id, &payload); err != nil {
			return nil, err
		}
		idArray := (*common.SHA256Output)(id)
		m[*idArray] = payload
	}

	// Sort them in the same order as the IDs.
	payloads := make([][]byte, len(IDs))
	for i, id := range IDs {
		payloads[i] = m[*id]
	}

	return payloads, nil
}
