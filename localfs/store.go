package localfs

import (
	"crypto/x509"
	"io"
	"net/mail"
	"os"
	"path/filepath"

	"github.com/lestrrat/go-cloud-acmeagent/store"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/lestrrat/go-pdebug"
)

/*
prefix: {{letsencrypt-base}}/aaa-agent/

Per Store instance:
{{email}}/info
  - registration.json -- the registration info
  - privkey.jwk  -- the account private key in JWK

{{email}}/domain/{{domain}}/
  - authz.json    -- the authorization result
  - privkey.pem   -- the private key in PEM
  - fullchain.pem -- the cert + intermediates
  - cert.pem      -- the cert only
  - chain.pem     -- the intermediate only
*/

func New(opts StorageOptions) (*Storage, error) {
	s := Storage{
		Root: opts.Root,
		ID:   opts.ID,
	}

	if s.Root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		s.Root = wd
	}

	if s.ID == "" { // ID must be an email...
		return nil, ErrInvalidID
	}

	if _, err := mail.ParseAddress(s.ID); err != nil {
		return nil, ErrInvalidID
	}

	return &s, nil
}

func (s Storage) pathTo(args ...string) string {
	l := append([]string{s.Root}, args...)
	return filepath.Join(l...)
}

type readerFn func(io.Reader, interface{}) error
func (s Storage) readObject(path string, obj interface{}, reader readerFn) error {
	dst, err := os.Create(path)
	if err != nil {
		return err
	}
	defer dst.Close()

	return reader(dst, obj)
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a pointer to `acmeagent.Account`
func (s Storage) SaveAccount(acct interface{}) (err error) {
	path := s.pathTo(s.ID, "info", "account.json")
	if pdebug.Enabled {
		g := pdebug.Marker("localfs.Storage.SaveAccount (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.writeObject(path, acct, store.SaveAccount)
}

type writerFn func(io.Writer, interface{}) error

func (s Storage) writeObject(path string, obj interface{}, writer writerFn) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	dst, err := os.Create(path)
	if err != nil {
		return err
	}
	defer dst.Close()

	return writer(dst, obj)
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a pointer to `acmeagent.Account`
func (s Storage) LoadAccount(acct interface{}) (err error) {
	path := s.pathTo(s.ID, "info", "account.json")
	if pdebug.Enabled {
		g := pdebug.Marker("localfs.Storage.LoadAccount (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, acct, store.LoadAccount)
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a `acmeagent.Authorization`
func (s Storage) SaveAuthorization(domain string, authz interface{}) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "authz.json")
	if pdebug.Enabled {
		g := pdebug.Marker("localfs.Storage.SaveAuthorization (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.writeObject(path, authz, store.SaveAuthorization)
}

func (s Storage) DeleteAuthorization(domain string) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "authz.json")
	if pdebug.Enabled {
		g := pdebug.Marker("localfs.Storage.DeleteAuthorization (%s)", path).BindError(&err)
		defer g.End()
	}

	return os.Remove(path)
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a pointer to `acmeagent.Authorization`
func (s Storage) LoadAuthorization(domain string, authz interface{}) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "authz.json")
	if pdebug.Enabled {
		g := pdebug.Marker("localfs.Storage.LoadAuthorization (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, authz, store.LoadAuthorization)
}

func (s Storage) SaveKey(k *jwk.RsaPrivateKey) (err error) {
	path := s.pathTo(s.ID, "info", "privkey.jwk")
	if pdebug.Enabled {
		g := pdebug.Marker("localfs.Storage.SaveKey (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.writeObject(path, k, store.SaveKey)
}

func (s Storage) LoadKey(key *jwk.RsaPrivateKey) (err error) {
	path := s.pathTo(s.ID, "info", "privkey.jwk")
	if pdebug.Enabled {
		g := pdebug.Marker("localfs.Storage.LoadKey (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, key, store.LoadKey)
}

func (s Storage) SaveCertKey(domain string, k *jwk.RsaPrivateKey) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "privkey.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("localfs.Storage.SaveCertKey (%s)", path).BindError(&err)
		defer g.End()
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	dst, err := os.Create(path)
	if err != nil {
		return err
	}
	defer dst.Close()

	return store.SaveCertKey(dst, k)
}

func (s Storage) LoadCertKey(domain string, key *jwk.RsaPrivateKey) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "privkey.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("localfs.Storage.LoadCertKey (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, key, store.LoadCertKey)
}

func (s Storage) SaveCert(domain string, issuerCert, myCert *x509.Certificate) (err error) {
	if pdebug.Enabled {
		g := pdebug.Marker("localfs.Storage.SaveCert").BindError(&err)
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
		g := pdebug.Marker("localfs.Storage.DeleteCert (%s)", domain).BindError(&err)
		defer g.End()
	}
	paths := []string{
		s.pathTo(s.ID, "domains", domain, "cert.pem"),
		s.pathTo(s.ID, "domains", domain, "chain.pem"),
		s.pathTo(s.ID, "domains", domain, "fullchain.pem"),
	}

	for _, path := range paths {
		if err := os.Remove(path); err != nil {
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
		g := pdebug.Marker("localfs.Storage.LoadCert (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, cert, store.LoadCert)
}

func (s Storage) LoadCertIssuer(domain string, cert *x509.Certificate) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "chain.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("localfs.Storage.LoadCertIssuer (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, cert, store.LoadCert)
}

func (s Storage) LoadCertFullChain(domain string, cert *x509.Certificate) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "fullchain.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("localfs.Storage.LoadCertFullChain (%s)", path).BindError(&err)
		defer g.End()
	}

	return s.readObject(path, cert, store.LoadCert)
}
