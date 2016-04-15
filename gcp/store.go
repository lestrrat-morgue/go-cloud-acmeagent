// +build !k8s

package gcp

import (
	"crypto/x509"
	"io"
	"path"

	"golang.org/x/net/context"

	"github.com/lestrrat/go-cloud-acmeagent/store"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/lestrrat/go-pdebug"
	"google.golang.org/cloud/storage"
)

func NewStorage(cl *storage.Client, projectID, email, bucketName string) *Storage {
	return &Storage{
		Client:     cl,
		BucketName: bucketName,
		ID:         email,
		Project:    projectID,
	}
}

func (s Storage) pathTo(args ...string) string {
	return path.Join(args...)
}

type readerFn func(io.Reader, interface{}) error
func (s Storage) readObject(path string, obj interface{}, reader readerFn) error {
	ctx := context.Background()
	b := s.Client.Bucket(s.BucketName)
	src, err := b.Object(path).NewReader(ctx)
	if err != nil {
		return err
	}
	if err := reader(src, obj); err != nil {
		return err
	}
	defer src.Close()
	return nil
}

type writerFn func(io.Writer, interface{}) error
func (s Storage) writeObject(path string, obj interface{}, writer writerFn) error {
	ctx := context.Background()
	b := s.Client.Bucket(s.BucketName)
	dst := b.Object(path).NewWriter(ctx)
	if err := writer(dst, obj); err != nil {
		return err
	}
	defer dst.Close()
	return nil
}

func (s Storage) deleteObject(path string) error {
	ctx := context.Background()
	b := s.Client.Bucket(s.BucketName)
	obj := b.Object(path)
	return obj.Delete(ctx)
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a pointer to `acmeagent.Account`
func (s Storage) SaveAccount(acct interface{}) (err error) {
	path := s.pathTo(s.ID, "info", "account.json")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.SaveAccount (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.writeObject(path, acct, store.SaveAccount)
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a pointer to `acmeagent.Account`
func (s Storage) LoadAccount(acct interface{}) (err error) {
	path := s.pathTo(s.ID, "info", "account.json")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadAccount (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, acct, store.LoadAccount)
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a `acmeagent.Authorization`
func (s Storage) SaveAuthorization(domain string, authz interface{}) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "authz.json")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.SaveAuthorization (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.writeObject(path, authz, store.SaveAuthorization)
}

func (s Storage) DeleteAuthorization(domain string) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "authz.json")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.DeleteAuthorization (%s)", path).BindError(&err)
		defer g.End()
	}
	return s.deleteObject(path)
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a pointer to `acmeagent.Authorization`
func (s Storage) LoadAuthorization(domain string, authz interface{}) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "authz.json")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadAuthorization (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, authz, store.LoadAuthorization)
}

func (s Storage) SaveKey(key *jwk.RsaPrivateKey) (err error) {
	path := s.pathTo(s.ID, "info", "privkey.jwk")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.SaveKey (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.writeObject(path, key, store.SaveKey)
}

func (s Storage) LoadKey(key *jwk.RsaPrivateKey) (err error) {
	path := s.pathTo(s.ID, "info", "privkey.jwk")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadKey (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, key, store.LoadKey)
}

func (s Storage) SaveCertKey(domain string, k *jwk.RsaPrivateKey) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "privkey.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.SaveCertKey (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.writeObject(path, k, store.SaveCertKey)
}

func (s Storage) LoadCertKey(domain string, key *jwk.RsaPrivateKey) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "privkey.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadCertKey (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, key, store.LoadCertKey)
}

func (s Storage) SaveCert(domain string, issuerCert, myCert *x509.Certificate) (err error) {
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.SaveCert").BindError(&err)
		defer g.End()
	}

	names := []string{"fullchain.pem", "cert.pem", "chain.pem"}
	certs := [][]*x509.Certificate{
		[]*x509.Certificate{myCert, issuerCert},
		[]*x509.Certificate{myCert},
		[]*x509.Certificate{issuerCert},
	}

	for i := 0; i < 3; i++ {
		path := s.pathTo(s.ID, "domains", domain, names[i])

		if err := s.writeObject(path, certs[i], store.SaveCert); err != nil {
			return err
		}
	}
	return nil
}

func (s Storage) DeleteCert(domain string) (err error) {
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.DeleteCert (%s)", domain).BindError(&err)
		defer g.End()
	}

	paths := []string{
		s.pathTo(s.ID, "domains", domain, "cert.pem"),
		s.pathTo(s.ID, "domains", domain, "chain.pem"),
		s.pathTo(s.ID, "domains", domain, "fullchain.pem"),
	}
	for _, path := range paths {
		if err := s.deleteObject(path); err != nil {
			// report, but do not stop on error
			if pdebug.Enabled {
				pdebug.Printf("Error while deleting %s: %s", path, err)
			}
		}
	}
	return nil
}

func (s Storage) LoadCert(domain string, cert *x509.Certificate) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "cert.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadCert (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, cert, store.LoadCert)
}

func (s Storage) LoadCertIssuer(domain string, cert *x509.Certificate) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "chain.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadCertIssuer (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, cert, store.LoadCert)
}

func (s Storage) LoadCertFullChain(domain string, cert *x509.Certificate) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "fullchain.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadCertFullChain (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, cert, store.LoadCert)
}
