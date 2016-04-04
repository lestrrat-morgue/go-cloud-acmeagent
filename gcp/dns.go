package gcp

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/lestrrat/go-pdebug"

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

func (c *CloudDNSComplete) lookupChallengeRecord(domain string) (*dns.ResourceRecordSet, error) {
	fqdn := "_acme-challenge." + domain + "."

	rrres, err := c.Service.ResourceRecordSets.List(c.Project, c.Zone).Do()
	if err != nil {
		return nil, err
	}

	for _, rr := range rrres.Rrsets {
		if rr.Kind != "dns#resourceRecordSet" {
			continue
		}

		if rr.Name != fqdn {
			continue
		}

		return rr, nil
	}
	return nil, errors.New("resource not found")
}

func (c *CloudDNSComplete) Cleanup(domain, token string) (err error) {
	if pdebug.Enabled {
		g := pdebug.Marker("CloudDNSComplete.Cleanup(%s, %s)", domain, token).BindError(&err)
		defer g.End()
	}

	// Deleting the resource record set requires a pretty complete
	// set of data. As such, it's much easier if we just look it up
	// and use that data to set the Deletions field
	var del *dns.ResourceRecordSet
	if rr, err := c.lookupChallengeRecord(domain); err == nil {
		del = rr
	}

	if del == nil {
		// Nothing to do
		return nil
	}

	// Send this to CloudDNS to create DNS entry
	ch := dns.Change{
		Deletions: []*dns.ResourceRecordSet{del},
	}

	if _, err := c.Service.Changes.Create(c.Project, c.Zone, &ch).Do(); err != nil {
		return err
	}
	return nil
}

// Complete attempts to fulfill a dns-01 challenge using Google CloudDNS.
func (c *CloudDNSComplete) Complete(domain, token string) (err error) {
	if pdebug.Enabled {
		g := pdebug.Marker("CloudDNSComplete.Complete(%s, %s)", domain, token).BindError(&err)
		defer g.End()
	}

	fqdn := "_acme-challenge." + domain + "."
	hasher := crypto.SHA256.New()
	fmt.Fprint(hasher, token)
	sum := hasher.Sum(nil)
	v := base64.RawURLEncoding.EncodeToString(sum)

	// Check if this record already exists
	var del *dns.ResourceRecordSet
	if rr, err := c.lookupChallengeRecord(domain); err == nil {
		del = rr
	}

	// Send this to CloudDNS to create DNS entry
	ch := dns.Change{
		Additions: []*dns.ResourceRecordSet{
			&dns.ResourceRecordSet{
				Kind:    "dns#resourceRecordSet",
				Name:    fqdn,
				Rrdatas: []string{v},
				Ttl:     10,
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

	// Wait for the record to be available
	timeout := time.After(30 * time.Second)
	ticker := time.Tick(time.Second)
	for {
		select {
		case <-timeout:
			return errors.New("timed out waiting for DNS record to be available")
		case <-ticker:
			txt, err := net.LookupTXT(fqdn)
			if err != nil {
				if pdebug.Enabled {
					pdebug.Printf("Failed to lookup TXT record for %s: %s", fqdn, err)
				}
			} else {
				if pdebug.Enabled {
					pdebug.Printf("looked up TXT records for %s, got %d entries", fqdn, len(txt))
					pdebug.Printf("now looking for value %s...", v)
				}
				for i, txtv := range txt {
					if pdebug.Enabled {
						pdebug.Printf("TXT record #%d: %s", i, txtv)
					}
					if txtv == v {
						goto DnsReady
					}
				}
			}
		}
	}

DnsReady:
	return nil
}
