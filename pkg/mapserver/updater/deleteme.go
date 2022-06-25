package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
)

// functions for measuring the bottlemeck

func (u *MapUpdater) UpdateNextBatchReturnTimeList(ctx context.Context) (int, []string, []string, error) {
	certs, err := u.Fetcher.NextBatch(ctx)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("CollectCerts | GetCertMultiThread | %w", err)
	}
	names := parseCertDomainName(certs)
	timeList, err := u.updateCertsReturnTime(ctx, certs)
	return len(certs), timeList, names, err
}

func (mapUpdater *MapUpdater) updateCertsReturnTime(ctx context.Context, certs []*ctx509.Certificate) (
	[]string, error) {

	timeList := []string{}
	totalStart := time.Now()
	start := time.Now()
	keyValuePairs, _, times, err :=
		mapUpdater.UpdateDomainEntriesTableUsingCertsReturnTime(ctx, certs)
	if err != nil {
		return nil, fmt.Errorf("CollectCerts | UpdateDomainEntriesUsingCerts | %w", err)
	}
	end := time.Now()
	fmt.Println()
	fmt.Println("============================================")
	fmt.Println("(db and memory) time to update domain entries: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	if len(keyValuePairs) == 0 {
		return nil, nil
	}

	keyInput, valueInput, err := keyValuePairToSMTInput(keyValuePairs)
	if err != nil {
		return nil, fmt.Errorf("CollectCerts | keyValuePairToSMTInput | %w", err)
	}

	start = time.Now()
	_, err = mapUpdater.smt.Update(ctx, keyInput, valueInput)
	if err != nil {
		return nil, fmt.Errorf("CollectCerts | Update | %w", err)
	}
	end = time.Now()

	fmt.Println()
	fmt.Println("============================================")
	fmt.Println("(memory) time to update tree in memory: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	totalEnd := time.Now()

	timeList = append(timeList, totalEnd.Sub(totalStart).String())
	timeList = append(timeList, times...)

	return timeList, nil
}

// UpdateDomainEntriesTableUsingCerts: Update the domain entries using the domain certificates
func (mapUpdater *MapUpdater) UpdateDomainEntriesTableUsingCertsReturnTime(ctx context.Context,
	certs []*x509.Certificate) ([]*db.KeyValuePair, int, []string, error) {

	timeList := []string{}
	if len(certs) == 0 {
		return nil, 0, nil, nil
	}

	start := time.Now()
	// get the unique list of affected domains
	affectedDomainsMap, domainCertMap := getAffectedDomainAndCertMap(certs)
	end := time.Now()
	fmt.Println("(memory) time to process certs: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	// if no domain to update
	if len(affectedDomainsMap) == 0 {
		return nil, 0, nil, nil
	}

	start = time.Now()
	// retrieve (possibly)affected domain entries from db
	// It's possible that no records will be changed, because the certs are already recorded.
	domainEntriesMap, err := mapUpdater.retrieveAffectedDomainFromDB(ctx, affectedDomainsMap)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | retrieveAffectedDomainFromDB | %w", err)
	}
	end = time.Now()
	fmt.Println("(db)     time to retrieve domain entries: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	start = time.Now()
	// update the domain entries
	updatedDomains, err := updateDomainEntries(domainEntriesMap, domainCertMap)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | updateDomainEntries | %w", err)
	}
	end = time.Now()
	fmt.Println("(db)     time to update domain entries: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	// if during this updates, no cert is added, directly return
	if len(updatedDomains) == 0 {
		return nil, 0, nil, nil
	}

	start = time.Now()
	// get the domain entries only if they are updated, from DB
	domainEntriesToWrite, err := getDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | getDomainEntriesToWrite | %w", err)
	}

	// serialized the domainEntry -> key-value pair
	keyValuePairs, err := serializeUpdatedDomainEntries(domainEntriesToWrite)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | serializeUpdatedDomainEntries | %w", err)
	}
	end = time.Now()
	fmt.Println("(memory) time to process updated domains: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	start = time.Now()
	// commit changes to db
	num, err := mapUpdater.writeChangesToDB(ctx, keyValuePairs)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | writeChangesToDB | %w", err)
	}
	end = time.Now()
	fmt.Println("(db)     time to write updated domain entries: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	return keyValuePairs, num, timeList, nil
}

func parseCertDomainName(certs []*ctx509.Certificate) []string {
	result := []string{}
	for _, cert := range certs {
		_, err := domain.ParseDomainName(cert.Subject.CommonName)
		if err == nil {
			result = append(result, cert.Subject.CommonName)
		}
	}
	return result
}
