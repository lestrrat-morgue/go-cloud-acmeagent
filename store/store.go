package store

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"

	"github.com/lestrrat/go-jwx/jwk"
)

func assertRsaPrivateKey(k interface{}) (*jwk.RsaPrivateKey, error) {
	privkey, ok := k.(*jwk.RsaPrivateKey)
	if !ok {
		return nil, errors.New("key must be a jwk.RsaPrivateKey instance")
	}
	return privkey, nil
}

// Parameter `acct` is an interface{} to avoid circular dependencies.
// In reality this must be a `acmeagent.Account`
func SaveAccount(dst io.Writer, acct interface{}) error {
	return json.NewEncoder(dst).Encode(acct)
}

// Parameter `acct` is an interface{} to avoid circular dependencies.
// In reality this must be a pointer to `acmeagent.Account`
func LoadAccount(src io.Reader, acct interface{}) error {
	return json.NewDecoder(src).Decode(acct)
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a `acmeagent.Authorization`
func SaveAuthorization(dst io.Writer, authz interface{}) error {
	return json.NewEncoder(dst).Encode(authz)
}

// Parameter `authz` is an interface{} to avoid circular dependencies.
// In reality this must be a pointer to `acmeagent.Authorization`
func LoadAuthorization(src io.Reader, authz interface{}) error {
	return json.NewDecoder(src).Decode(authz)
}

// SaveKey writes the contents of k into dst. Parameter k must be
// a pointer to `jwk.PrivateKey`
func SaveKey(dst io.Writer, k interface{}) error {
	privjwk, err := assertRsaPrivateKey(k)
	if err != nil {
		return err
	}

	return json.NewEncoder(dst).Encode(privjwk)
}

func LoadKey(src io.Reader, key interface{}) error {
	var v jwk.RsaPrivateKey
	if err := json.NewDecoder(src).Decode(&v); err != nil {
		return err
	}
	key = &v

	return nil
}

func SaveCertKey(dst io.Writer, key interface{}) error {
	privjwk, err := assertRsaPrivateKey(key)
	if err != nil {
		return err
	}

	privkey, err := privjwk.PrivateKey()
	if err != nil {
		return err
	}
	buf := bytes.Buffer{}
	if err := pem.Encode(&buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privkey)}); err != nil {
		return err
	}

	if _, err = buf.WriteTo(dst); err != nil {
		return err
	}
	return nil
}

func LoadCertKey(src io.Reader, key interface{}) error {
	buf, err := ioutil.ReadAll(src)
	if err != nil {
		return err
	}

	derBlock, _ := pem.Decode(buf)
	k, err := x509.ParsePKCS1PrivateKey(derBlock.Bytes)
	if err != nil {
		return err
	}

	privjwk, err := jwk.NewRsaPrivateKey(k)
	if err != nil {
		return err
	}
	key = privjwk
	return nil
}

func SaveCert(dst io.Writer, in interface{}) error {
	var certs []*x509.Certificate
	switch in.(type) {
	case *x509.Certificate:
		certs = []*x509.Certificate{in.(*x509.Certificate)}
	case []*x509.Certificate:
		certs = in.([]*x509.Certificate)
	default:
		return errors.New("expected []*x509.Certificate or *x509.Certificate")
	}

	buf := bytes.Buffer{}
	for _, cert := range certs {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
	}

	if _, err := buf.WriteTo(dst); err != nil {
		return err
	}
	return nil
}

func LoadCert(src io.Reader, cert interface{}) error {
	buf, err := ioutil.ReadAll(src)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(buf)
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	return nil
}
