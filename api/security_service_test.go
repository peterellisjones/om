package api_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-cf/om/api"
	"github.com/pivotal-cf/om/api/fakes"
)

var _ = Describe("SecurityService", func() {
	var (
		client  *fakes.HttpClient
		service api.SecurityService
	)

	BeforeEach(func() {
		client = &fakes.HttpClient{}
		service = api.NewSecurityService(client)
	})

	Describe("Fetch Root CA Cert", func() {
		It("gets the root CA cert", func() {
			client.DoReturns(&http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(strings.NewReader(`{"root_ca_certificate_pem": "some-response-cert"}`)),
			}, nil)

			output, err := service.FetchRootCACert()
			Expect(err).NotTo(HaveOccurred())

			request := client.DoArgsForCall(0)
			Expect(request.Method).To(Equal("GET"))
			Expect(request.URL.Path).To(Equal("/api/v0/security/root_ca_certificate"))
			Expect(output).To(Equal("some-response-cert"))
		})

		Context("error cases", func() {
			It("returns error if request fails to submit", func() {
				client.DoReturns(&http.Response{}, errors.New("some-error"))

				_, err := service.FetchRootCACert()
				Expect(err).To(MatchError("failed to submit request: some-error"))
			})

			It("returns error when response contains non-200 status code", func() {
				client.DoReturns(&http.Response{
					StatusCode: http.StatusTeapot,
					Body:       ioutil.NopCloser(strings.NewReader(`{}`)),
				}, nil)

				_, err := service.FetchRootCACert()
				Expect(err).To(MatchError(ContainSubstring("could not make api request: unexpected response")))
			})

			It("returns error if response fails to unmarshal", func() {
				client.DoReturns(&http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(strings.NewReader(`%%%`)),
				}, nil)

				_, err := service.FetchRootCACert()
				Expect(err).To(MatchError(ContainSubstring("failed to unmarshal response: invalid character")))
			})
		})
	})

	FDescribe("Generate RSA Cert", func() {
		var caCert []byte
		var caTemplate *x509.Certificate

		BeforeEach(func() {
			// create a template for the CA certificate
			caTemplate = &x509.Certificate{
				SerialNumber: big.NewInt(1234),
				Subject: pkix.Name{
					CommonName:   "ca.localhost",
					Country:      []string{"US"},
					Organization: []string{"Pivotal"},
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().AddDate(5, 5, 5),
				SubjectKeyId:          []byte{1, 2, 3, 4, 5},
				BasicConstraintsValid: true,
				IsCA:        true,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			}

			// generate the CA private key used to sign certificates
			caPrivatekey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())

			// create a self-signed certificate for the CA. template = parent
			caCert, err = x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivatekey.PublicKey, caPrivatekey)
			Expect(err).NotTo(HaveOccurred())

			// read the signed CA certificate back into the template
			caTemplate, err = x509.ParseCertificate(caCert)
			Expect(err).NotTo(HaveOccurred())

			// verify that the CA certificate is validly self-signed
			err = caTemplate.CheckSignatureFrom(caTemplate)
			Expect(err).NotTo(HaveOccurred())

			// encode the CA certificate as PEM bytes
			caCert = pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: caCert,
			})
		})

		It("generates an RSA cert from given parent", func() {
			cert, err := service.GenerateRSACert(caCert, []string{"*.apps.example.com", "*.sys.example.com"})
			Expect(err).NotTo(HaveOccurred())

			generatedCert, err := x509.ParseCertificate(cert)
			Expect(err).NotTo(HaveOccurred())

			fmt.Printf("%+v\n", generatedCert)

			err = generatedCert.CheckSignatureFrom(caTemplate)
			Expect(err).NotTo(HaveOccurred())

			Expect(generatedCert.Subject.Names).To(Equal([]string{"*.apps.example.com", "*.sys.example.com"}))
		})
	})
})
