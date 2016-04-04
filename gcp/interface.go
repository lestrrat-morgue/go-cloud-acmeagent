package gcp

import (
	"google.golang.org/api/dns/v1"
)

type CloudDNSComplete struct {
	Project string       // GCP project name, like "foobar-123"
	Service *dns.Service // Google API for CloudDNS. Must be properly OAuth'ed
	Zone    string       // GCP CloudDNS zone name
}
