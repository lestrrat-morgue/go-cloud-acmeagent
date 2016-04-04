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
	fqdn := "_acme-challenge." + domain + "."
	hasher := crypto.SHA256.New()
	fmt.Fprint(hasher, token)
	sum := hasher.Sum(nil)
	v := base64.RawURLEncoding.EncodeToString(sum)

	// Check if this record already exists
	rrres, err := c.Service.ResourceRecordSets.List(c.Project, c.Zone).Do()
	if err != nil {
		return err
	}

	var del *dns.ResourceRecordSet
	for _, rr := range rrres.Rrsets {
		if rr.Kind != "dns#resourceRecordSet" {
			continue
		}

		if rr.Name != fqdn {
			continue
		}
		del = rr
		break
	}

	// Send this to CloudDNS to create DNS entry
	ch := dns.Change{
		Additions: []*dns.ResourceRecordSet{
			&dns.ResourceRecordSet{
				Kind:    "dns#resourceRecordSet",
				Name:    fqdn,
				Rrdatas: []string{v},
				Ttl:     300,
				Type:    "TXT",
			},
		},
	}

	if del != nil {
		ch.Deletions = []*dns.ResourceRecordSet{del}
	}

	if _, err := c.Service.Changes.Create(c.Project, c.Zone, &ch).Do(); err != nil {
		return err
	}

	return nil
}
