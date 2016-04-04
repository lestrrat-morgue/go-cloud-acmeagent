package gcp

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"google.golang.org/api/dns/v1"
)

// NewDNS creates a service that attempts to fulfill the dns-01
// challenge using Google CloudDNS.
func NewDNS(s *dns.Service, projectID, zoneName string) *CloudDNSComplete {
	return &CloudDNSComplete{
		Project: projectID,
		Service: s,
		Zone:    zoneName,
	}
}

// Complete attempts to fulfill a dns-01 challenge using Google CloudDNS.
func (c *CloudDNSComplete) Complete(domain, token string) error {
	hasher := crypto.SHA256.New()
	fmt.Fprint(hasher, token)
	sum := hasher.Sum(nil)
	v := base64.RawURLEncoding.EncodeToString(sum)

	// Send this to CloudDNS to create DNS entry
	ch := dns.Change{
		Additions: []*dns.ResourceRecordSet{
			&dns.ResourceRecordSet{
				Kind:    "dns#resourceRecordSet",
				Name:    "_acme-challenge." + domain + ".",
				Rrdatas: []string{v},
				Ttl:     300,
				Type:    "TXT",
			},
		},
	}

	if _, err := c.Service.Changes.Create(c.Project, c.Zone, &ch).Do(); err != nil {
		return err
	}

	return nil
}
