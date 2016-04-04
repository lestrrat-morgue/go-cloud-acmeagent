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

func assertRsaPrivateKey(k jwk.Key) (*jwk.RsaPrivateKey, error) {
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

// SaveKey writes the contents of k into dst
func SaveKey(dst io.Writer, k jwk.Key) error {
	privjwk, err := assertRsaPrivateKey(k)
	if err != nil {
		return err
	}

	return json.NewEncoder(dst).Encode(privjwk)
}

func LoadKey(src io.Reader) (*jwk.RsaPrivateKey, error) {
	var key jwk.RsaPrivateKey
	if err := json.NewDecoder(src).Decode(&key); err != nil {
		return nil, err
	}

	return &key, nil
}

func SaveCertKey(dst io.Writer, privjwk *jwk.RsaPrivateKey) error {
	privkey, err := privjwk.PrivateKey()
	if err != nil {
		return err
	}
	buf := bytes.Buffer{}
	if err := pem.Encode(&buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privkey)}); err != nil {
		return err
	}

	_, err = buf.WriteTo(dst)
	if err != nil {
		return err
	}
	return nil
}

func LoadCertKey(src io.Reader) (*jwk.RsaPrivateKey, error) {
	buf, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, err
	}

	derBlock, _ := pem.Decode(buf)
	key, err := x509.ParsePKCS1PrivateKey(derBlock.Bytes)
	if err != nil {
		return nil, err
	}

	privjwk, err := jwk.NewRsaPrivateKey(key)
	if err != nil {
		return nil, err
	}

	return privjwk, nil
}

func SaveCert(dst io.Writer, certs ...*x509.Certificate) error {
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

func LoadCert(src io.Reader) (*x509.Certificate, error) {
	buf, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf)
	return x509.ParseCertificate(block.Bytes)
}
