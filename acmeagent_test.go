package acmeagent_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat/go-cloud-acmeagent"
	"github.com/lestrrat/go-cloud-acmeagent/gcp"
	"github.com/lestrrat/go-cloud-acmeagent/localfs"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
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

	store, err := localfs.New(localfs.StorageOptions{
		Root: filepath.Join(wd, "acme"),
		ID:   email,
	})
	if !assert.NoError(t, err, "Creating localfs state storage should succeed") {
		return
	}

	var authz acmeagent.Authorization
	if err := store.LoadAuthorization(domain, &authz); err != nil || !authz.IsExpired() {
		return // no auth necessary
	}

	// Get your challange fulfilling strategy ready. Here we're
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

	dnssvc, err := dns.New(httpcl)
	if !assert.NoError(t, err, "creating new DNS service should succeed") {
		return
	}

	// Tell the agent which challenges we can accept
	aa, err := acmeagent.New(acmeagent.AgentOptions{
		DNSCompleter: gcp.NewDNS(dnssvc, gcpproj, gcpzone),
		StateStorage: store,
	})

	// With us so far? now fire the request, and let the authorization happen
	if !assert.NoError(t, aa.AuthorizeForDomain(domain), "authorize should succeed") {
		return
	}
}