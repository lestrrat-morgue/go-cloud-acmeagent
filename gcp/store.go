package gcp

import (
	"bytes"
	"crypto/x509"
	"path"

	"github.com/lestrrat/go-cloud-acmeagent/store"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/lestrrat/go-pdebug"
	"google.golang.org/api/storage/v1"
)

func NewStorage(s *storage.Service, projectID, email, bucketName string) *Storage {
	return &Storage{
		Service:    s,
		BucketName: bucketName,
		ID:         email,
		Project:    projectID,
	}
}

func (s Storage) pathTo(args ...string) string {
	l := append([]string{s.BucketName}, args...)
	return path.Join(l...)
}

func (s Storage) assertBucket() error {
	b, err := s.Service.Buckets.Get(s.BucketName).Do()
	if err == nil {
		return nil
	}

	b = &storage.Bucket{
		Name: s.BucketName,
	}

	if _, err := s.Service.Buckets.Insert(s.Project, b).Do(); err != nil {
		return err
	}
	return nil
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a pointer to `acmeagent.Account`
func (s Storage) SaveAccount(acct interface{}) (err error) {
	path := s.pathTo(s.ID, "info", "account.json")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.SaveAccount (%s)", path).BindError(&err)
		defer g.End()
	}

	if err := s.assertBucket(); err != nil {
		return err
	}

	dst := bytes.Buffer{}
	if err := store.SaveAccount(&dst, acct); err != nil {
		return err
	}

	object := storage.Object{
		Name: path,
	}
	if _, err := s.Service.Objects.Insert(s.BucketName, &object).Media(&dst).Do(); err != nil {
		return err
	}
	return nil
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a pointer to `acmeagent.Account`
func (s Storage) LoadAccount(acct interface{}) (err error) {
	path := s.pathTo(s.ID, "info", "account.json")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadAccount (%s)", path).BindError(&err)
		defer g.End()
	}

	res, err := s.Service.Objects.Get(s.BucketName, path).Download()
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return store.LoadAccount(res.Body, acct)
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a `acmeagent.Authorization`
func (s Storage) SaveAuthorization(domain string, authz interface{}) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "authz.json")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.SaveAuthorization (%s)", path).BindError(&err)
		defer g.End()
	}

	if err := s.assertBucket(); err != nil {
		return err
	}

	dst := bytes.Buffer{}
	if err := store.SaveAuthorization(&dst, authz); err != nil {
		return err
	}

	object := storage.Object{
		Name: path,
	}
	if _, err := s.Service.Objects.Insert(s.BucketName, &object).Media(&dst).Do(); err != nil {
		return err
	}
	return nil
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a pointer to `acmeagent.Authorization`
func (s Storage) LoadAuthorization(domain string, authz interface{}) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "authz.json")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadAuthorization (%s)", path).BindError(&err)
		defer g.End()
	}

	res, err := s.Service.Objects.Get(s.BucketName, path).Download()
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return store.LoadAuthorization(res.Body, authz)
}

func (s Storage) SaveKey(k *jwk.RsaPrivateKey) (err error) {
	path := s.pathTo(s.ID, "info", "privkey.jwk")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.SaveKey (%s)", path).BindError(&err)
		defer g.End()
	}

	if err := s.assertBucket(); err != nil {
		return err
	}

	dst := bytes.Buffer{}
	if err := store.SaveKey(&dst, k); err != nil {
		return err
	}

	object := storage.Object{
		Name: path,
	}
	if _, err := s.Service.Objects.Insert(s.BucketName, &object).Media(&dst).Do(); err != nil {
		return err
	}
	return nil
}

func (s Storage) LoadKey() (key *jwk.RsaPrivateKey, err error) {
	path := s.pathTo(s.ID, "info", "privkey.jwk")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadKey (%s)", path).BindError(&err)
		defer g.End()
	}

	res, err := s.Service.Objects.Get(s.BucketName, path).Download()
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return store.LoadKey(res.Body)
}

func (s Storage) SaveCertKey(domain string, k *jwk.RsaPrivateKey) (err error) {
	path := s.pathTo(s.ID, "domains", domain, "privkey.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.SaveCertKey (%s)", path).BindError(&err)
		defer g.End()
	}

	if err := s.assertBucket(); err != nil {
		return err
	}

	dst := bytes.Buffer{}
	if err := store.SaveCertKey(&dst, k); err != nil {
		return err
	}

	object := storage.Object{
		Name: path,
	}
	if _, err := s.Service.Objects.Insert(s.BucketName, &object).Media(&dst).Do(); err != nil {
		return err
	}
	return nil
}

func (s Storage) LoadCertKey(domain string) (key *jwk.RsaPrivateKey, err error) {
	path := s.pathTo(s.ID, "domains", domain, "privkey.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadCertKey (%s)", path).BindError(&err)
		defer g.End()
	}

	res, err := s.Service.Objects.Get(s.BucketName, path).Download()
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return store.LoadCertKey(res.Body)
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

	if err := s.assertBucket(); err != nil {
		return err
	}

	for i := 0; i < 3; i++ {
		path := s.pathTo(s.ID, "domains", domain, names[i])
		dst := bytes.Buffer{}
		if err := store.SaveCert(&dst, certs[i]...); err != nil {
			return err
		}
		object := storage.Object{
			Name: path,
		}
		if _, err := s.Service.Objects.Insert(s.BucketName, &object).Media(&dst).Do(); err != nil {
			return err
		}
	}
	return nil
}

func (s Storage) LoadCert(domain string) (cert *x509.Certificate, err error) {
	path := s.pathTo(s.ID, "domains", domain, "cert.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadCert (%s)", path).BindError(&err)
		defer g.End()
	}

	res, err := s.Service.Objects.Get(s.BucketName, path).Download()
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return store.LoadCert(res.Body)
}

func (s Storage) LoadCertIssuer(domain string) (cert *x509.Certificate, err error) {
	path := s.pathTo(s.ID, "domains", domain, "chain.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadCertIssuer (%s)", path).BindError(&err)
		defer g.End()
	}

	res, err := s.Service.Objects.Get(s.BucketName, path).Download()
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return store.LoadCert(res.Body)
}

func (s Storage) LoadCertFullChain(domain string) (cert *x509.Certificate, err error) {
	path := s.pathTo(s.ID, "domains", domain, "fullchain.pem")
	if pdebug.Enabled {
		g := pdebug.Marker("gcp.Storage.LoadCertFullChain (%s)", path).BindError(&err)
		defer g.End()
	}

	res, err := s.Service.Objects.Get(s.BucketName, path).Download()
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return store.LoadCert(res.Body)
}
