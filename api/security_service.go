package api

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httputil"
	"time"
)

type SecurityService struct {
	client httpClient
}

type certResponse struct {
	Cert string `json:"root_ca_certificate_pem"`
}

func NewSecurityService(client httpClient) SecurityService {
	return SecurityService{client: client}
}

func (s SecurityService) FetchRootCACert() (string, error) {
	request, err := http.NewRequest("GET", "/api/v0/security/root_ca_certificate", nil)
	if err != nil {
		return "", fmt.Errorf("failed constructing request: %s", err)
	}

	response, err := s.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("failed to submit request: %s", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		out, err := httputil.DumpResponse(response, true)
		if err != nil {
			return "", fmt.Errorf("request failed: unexpected response: %s", err)
		}
		return "", fmt.Errorf("could not make api request: unexpected response.\n%s", out)
	}

	output, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	var certResponse certResponse
	err = json.Unmarshal(output, &certResponse)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %s", err)
	}

	return certResponse.Cert, nil
}

func (s SecurityService) GenerateRSACert(parent []byte, domains []string) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Pivotal"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	parentBlock, _ := pem.Decode(parent)

	parentCert, err := x509.ParseCertificate(parentBlock.Bytes)
	if err != nil {
		panic(err)
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, parentCert)
	if err != nil {
		panic(err)
	}

	return cert, nil
}
