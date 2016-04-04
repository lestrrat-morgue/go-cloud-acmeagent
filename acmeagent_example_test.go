package acmeagent_test

import (
	"github.com/lestrrat/go-cloud-acmeagent"
	"github.com/lestrrat/go-cloud-acmeagent/gcp"
	"github.com/lestrrat/go-cloud-acmeagent/localfs"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
)

func ExampleLocalfsStore() (acmeagent.StateStorage, error) {
	return localfs.New(localfs.StorageOptions{
		Root: "/path/to/storage",
		ID:   "lestrrat@gmail.com",
	})
}

func ExampleAuhtorization() {
	store, err := ExampleLocalfsStore()
	if err != nil {
		panic(err)
	}

	domain := "example.com"

	var authz acmeagent.Authorization
	if err := store.LoadAuthorization(domain, &authz); err == nil && !authz.IsExpired() {
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
	if err != nil {
		panic(err)
	}

	dnssvc, err := dns.New(httpcl)
	if err != nil {
		panic(err)
	}

	// Tell the agent which challenges we can accept
	aa, err := acmeagent.New(acmeagent.AgentOptions{
		DNSCompleter: gcp.NewDNS(dnssvc, "projectID", "zoneName"),
		StateStorage: store,
	})

	// With us so far? now fire the request, and let the authorization happen
	if err := aa.AuthorizeForDomain(domain); err != nil {
		panic(err)
	}

}