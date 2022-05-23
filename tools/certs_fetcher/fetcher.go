package main

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
)

func main() {
	startIdx := 1120000
	endIdx := 1120999

	start := time.Now()
	certs, _, err := logpicker.GetCertMultiThread("https://ct.googleapis.com/logs/argon2021", int64(startIdx), int64(endIdx), 20)
	if err != nil {
		panic(err)
	}
	end := time.Now()
	fmt.Println("time to download "+strconv.Itoa(len(certs))+" certs ", end.Sub(start))

	number := 1
	for _, cert := range certs {
		certBytes := CertToPEM(cert)
		err = ioutil.WriteFile("./testdata/"+cert.Subject.CommonName+strconv.Itoa(number)+".cer", certBytes, 0644)
		if err != nil {
			panic(err)
		}
		number = number + 1
	}

}

func CertToPEM(cert *x509.Certificate) []byte {
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return pemCert
}
