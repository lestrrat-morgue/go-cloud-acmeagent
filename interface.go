package acmeagent

import (
	"crypto/rsa"
	"crypto/x509"
	"sync"
	"time"

	"github.com/lestrrat/go-jwx/jwk"
	"github.com/lestrrat/go-jwx/jws"
)

const (
	DNSChallenge    = "dns-01"
	HTTPChallenge   = "http-01"
	TLSSNIChallenge = "tls-sni-01"
)
const joseContentType = "application/jose+json"
const LetsEncryptStagingURL = "https://acme-staging.api.letsencrypt.org/directory"
const LetsEncryptURL = "https://acme-v01.api.letsencrypt.org/directory"

var DefaultDirectoryURL = LetsEncryptURL

type ChallengeCompleter interface {
	Complete(domain, token string) error
	Cleanup(domain, token string) error
}

type CertificateUploader interface {
	Upload(name string, certs []*x509.Certificate, certkey *rsa.PrivateKey) error
}

type AgentOptions struct {
	// DirectoryURL is the location from where to fetch the
	// various endpoints. If not specified, DefaultDirectoryURL will
	// be used.
	DirectoryURL string

	// DNSCompleter, when specified, will be used to handle dns-01
	// challenges. If not specified, then dns-01 challenges will not
	// be considered.
	DNSCompleter ChallengeCompleter

	// XXX No HTTP Completer currently available
	HTTPCompleter ChallengeCompleter

	// XXX No TLSSNI Completer currently available
	TLSSNICompleter ChallengeCompleter

	// Uploader is responsible for uploading the certificates.
	Uploader CertificateUploader

	StateStorage StateStorage
}

type Challenge struct {
	URI              string     `json:"uri,omitempty"`
	Type             string     `json:"type"`
	Token            string     `json:"token"`
	KeyAuthorization string     `json:"keyAuthorization,omitempty"`
	Status           string     `json:"status,omitempty"`
	Error            *ACMEError `json:"error"`
}

// See https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-5.4
type ACMEError struct {
	StatusCode int
	Type       string `json:"type"`
	Detail     string `json:"detail"`
}

type directory struct {
	NewAuthz   string `json:"new-authz"`
	NewCert    string `json:"new-cert"`
	NewReg     string `json:"new-reg"`
	RevokeCert string `json:"revoke-cert"`
}

// Account to holds the registration information
type Account struct {
	URL       string
	TOS       string
	AgreedTOS time.Time
}

type Combination []int

type RegistrationRequest struct {
	Agreement      string   `json:"agreement"`
	Authorizations string   `json:"authorizations"`
	Certificates   string   `json:"certificates"`
	Contact        []string `json:"contact"`
}

type UpdateRegistrationRequest struct {
	Key       jwk.Key  `json:"key",omitempty`
	Contact   []string `json:"contact"`
	Agreement string   `json:"agreement,omitempty"`
}

type AuthorizationRequest struct {
	Identifier Identifier `json:"identifier"`
}

type Authorization struct {
	URL          string        `json:"url"` // URL is not included in the spec
	Status       string        `json:"status"`
	Expires      string        `json:"expires"`
	Identifier   Identifier    `json:"identifier"`
	Challenges   []Challenge   `json:"challenges"`
	Combinations []Combination `json:"combinations"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// StateStorage stores persistent data in appropriate places, such
// as in a local directory or in the cloud.
type StateStorage interface {
	LoadAccount(interface{}) error
	SaveAccount(interface{}) error

	SaveAuthorization(string, interface{}) error
	LoadAuthorization(string, interface{}) error
	// DeleteCert deletes the stored authorization
	DeleteAuthorization(string) error

	// SaveKey saves the private key in JWK format.
	// The key must be an RSA private key.
	SaveKey(*jwk.RsaPrivateKey) error

	// LoadKey loads the stored private key.
	LoadKey(*jwk.RsaPrivateKey) error

	// SaveCertKey saves the certificate private key in PEM format.
	// The key must be an RSA private key.
	SaveCertKey(string, *jwk.RsaPrivateKey) error

	LoadCertKey(string, *jwk.RsaPrivateKey) error

	SaveCert(string, *x509.Certificate, *x509.Certificate) error

	// LoadCert loads the stored certificate
	LoadCert(string, *x509.Certificate) error

	// DeleteCert deletes the stored certificate
	DeleteCert(string) error

	// LoadCertIssuer loads the issuer certificate
	LoadCertIssuer(string, *x509.Certificate) error

	// LoadCertFullchain loads the full chain certificate
	LoadCertFullChain(string, *x509.Certificate) error
}

type AcmeAgent struct {
	Store        StateStorage
	dnscc        ChallengeCompleter
	httpcc       ChallengeCompleter
	tlssnicc     ChallengeCompleter
	uploader     CertificateUploader
	signer       *jws.MultiSign
	privjwk      jwk.RsaPrivateKey
	privkey      *rsa.PrivateKey
	directoryURL string
	directory    directory
	initialized  bool
	initLock     sync.Mutex
}

type ChallengeCompletionRequest struct {
	Resource         string `json:"resource"`
	Type             string `json:"type"`
	Token            string `json:"token"`
	KeyAuthorization string `json:"keyAuthorization,omitempty"`
}

type CertificateRequest struct {
	Resource string `json:"resource"`
	CSR      string `json:"csr"`
}

const defaultRRSetTTL = 10
