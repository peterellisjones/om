package acceptance

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os/exec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("available-errands command", func() {
	var (
		server *httptest.Server
	)

	BeforeEach(func() {
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var responseString string
			w.Header().Set("Content-Type", "application/json")

			switch req.URL.Path {
			case "/uaa/oauth/token":
				responseString = `{
				"access_token": "some-opsman-token",
				"token_type": "bearer",
				"expires_in": 3600
			}`
			default:
				out, err := httputil.DumpRequest(req, true)
				Expect(err).NotTo(HaveOccurred())
				Fail(fmt.Sprintf("unexpected request: %s", out))
			}

			w.Write([]byte(responseString))
		}))
	})

	It("successfully displays all the errands", func() {
		command := exec.Command(pathToMain,
			"--target", server.URL,
		)
	})
})
