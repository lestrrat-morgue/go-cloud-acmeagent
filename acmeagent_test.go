package acmeagent_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lestrrat/go-cloud-acmeagent"
	"github.com/lestrrat/go-cloud-acmeagent/gcp"
	"github.com/lestrrat/go-cloud-acmeagent/localfs"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/storage/v1"
)

func TestAuthorizeGCP(t *testing.T) {
	email := os.Getenv("ACME_AGENT_TEST_EMAIL")
	if email == "" {
		t.Logf("ACME_AGENT_TEST_EMAIL environment variable is required for this test")
		return
	}
	domain := os.Getenv("ACME_AGENT_TEST_DOMAIN")
	if domain == "" {
		t.Logf("ACME_AGENT_TEST_DOMAIN environment variable is required for this test")
		return
	}
	gcpproj := os.Getenv("ACME_AGENT_TEST_GCP_PROJECT_ID")
	if gcpproj == "" {
		t.Logf("ACME_AGENT_TEST_GCP_PROJECT_ID environment variable is required for this test")
		return
	}
	gcpzone := os.Getenv("ACME_AGENT_TEST_GCP_ZONE_NAME")
	if gcpzone == "" {
		t.Logf("ACME_AGENT_TEST_GCP_ZONE_NAME environment variable is required for this test")
		return
	}

	wd, err := os.Getwd()
	if !assert.NoError(t, err, "Getting working directory should succeed") {
		return
	}

	// getting an object that can create appropriate DNS entries
	// using Google CloudDNS to respond to dns-01 challenge
	ctx := context.Background()
	httpcl, err := google.DefaultClient(
		ctx,
		dns.NdevClouddnsReadwriteScope, // We need to be able to update CloudDNS
	)
	if !assert.NoError(t, err, "creating new Google oauth'ed client should succeed") {
		panic(err)
	}

	var store acmeagent.StateStorage
	switch storetyp := os.Getenv("ACME_AGENT_TEST_STORE_TYPE"); storetyp {
	case "gcp":
		storagesvc, err := storage.New(httpcl)
		if !assert.NoError(t, err, "creating new Storage service should succeed") {
			return
		}
		store = gcp.NewStorage(storagesvc, gcpproj, email, "acme")
	default:
		store, err = localfs.New(localfs.StorageOptions{
			Root: filepath.Join(wd, "acme"),
			ID:   email,
		})
		if !assert.NoError(t, err, "creating localfs state storage should succeed") {
			return
		}
	}

	dnssvc, err := dns.New(httpcl)
	if !assert.NoError(t, err, "creating new DNS service should succeed") {
		return
	}

	computesvc, err := compute.New(httpcl)
	if !assert.NoError(t, err, "creating new Compute service should succeed") {
		return
	}

	// Tell the agent which challenges we can accept
	aa, err := acmeagent.New(acmeagent.AgentOptions{
		DNSCompleter: gcp.NewDNS(dnssvc, gcpproj, gcpzone),
		Uploader:     gcp.NewCertificateUpload(computesvc, gcpproj),
		StateStorage: store,
	})

	var acct acmeagent.Account
	if err := store.LoadAccount(&acct); err != nil {
		t.Logf("No account exists, registering...")
		if !assert.NoError(t, aa.Register(email), "Register should succeed") {
			return
		}
	}

	if cert, err := store.LoadCert(domain); err != nil || time.Now().After(cert.NotAfter) {
		var authz acmeagent.Authorization
		if err := store.LoadAuthorization(domain, &authz); err != nil || authz.IsExpired() {
			// No authorization, or is expired. Fire the authorization process
			if !assert.NoError(t, aa.AuthorizeForDomain(domain), "authorize should succeed") {
				return
			}
		}

		// We know we have authorizaiton, so issue the certificates
		if !assert.NoError(t, aa.IssueCertificate(domain, nil, false), "IssueCertificate should succeed") {
			return
		}
	}

	if !assert.NoError(t, aa.UploadCertificate(domain), "UploadCertificate should succeed") {
		return
	}

}