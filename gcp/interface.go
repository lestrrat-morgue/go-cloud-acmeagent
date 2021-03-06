// +build !k8s

package gcp

import (
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/cloud/storage"
)

type CloudDNSComplete struct {
	Project string       // GCP project name, like "foobar-123"
	Service *dns.Service // Google API for CloudDNS. Must be properly OAuth'ed
	Zone    string       // GCP CloudDNS zone name
}

type LBUpload struct {
	Project string           // GCP project name, like "foobar-123"
	Service *compute.Service // Google API for Compute Engine. Must be properly OAuth'ed
}

type Storage struct {
	BucketName string           // GCP bucket name, most likely "acme"
	Client     *storage.Client
	ID         string           // Email of the user
	Project    string           // GCP project name, like "foobar-123"
}
