package gcp

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"

	"google.golang.org/api/compute/v1"
)

func NewCertificateUpload(s *compute.Service, projectID string) *CertificateUpload {
	return &CertificateUpload{
		Project: projectID,
		Service: s,
	}
}

func (cu *CertificateUpload) Upload(name string, cert *x509.Certificate) error {
	// First, save to a local file
	dst, err := ioutil.TempFile("", "gcp-cert-upload-")
	if err != nil {
		return err
	}
	defer os.Remove(dst.Name())
	defer dst.Close()

	if err := pem.Encode(dst, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return err
	}
	if err := dst.Sync(); err != nil {
		return err
	}

	sslcert := compute.SslCertificate{
		Certificate: dst.Name(),
		Description: "Certificate generated by Let's Encrypt, uploaded by go-cloud-acmeagent",
	}
	if _, err := cu.Service.SslCertificates.Insert(cu.Project, &sslcert).Do(); err != nil {
		return err
	}
	return nil
}
