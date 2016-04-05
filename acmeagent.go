package acmeagent

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/lestrrat/go-pdebug"
	"github.com/tent/http-link-go"
)

// New creates a new AcmeAgent.
func New(opts AgentOptions) (*AcmeAgent, error) {
	agent := AcmeAgent{
		dnscc:        opts.DNSCompleter,
		httpcc:       opts.HTTPCompleter,
		tlssnicc:     opts.TLSSNICompleter,
		uploader:     opts.Uploader,
		directoryURL: opts.DirectoryURL,
		store:        opts.StateStorage,
	}

	if agent.store == nil {
		return nil, errors.New("opts.StateStore is required")
	}

	if agent.directoryURL == "" {
		agent.directoryURL = DefaultDirectoryURL
	}

	return &agent, nil
}

// initialize may be called multiple times, but is executed
// exactly once per lifecycle of an agent. its purpose is to
// send the initial request to Let's Encrypt to initiate the
// whole process.
func (aa *AcmeAgent) initialize() (err error) {
	aa.initLock.Lock()
	defer aa.initLock.Unlock()

	if aa.initialized {
		return nil
	}

	aa.privjwk, err = aa.store.LoadKey()
	if err != nil {
		return err
	}
	aa.privkey, err = aa.privjwk.PrivateKey()
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}

	rsaSigner, err := jws.NewRsaSign(jwa.RS256, aa.privkey)
	if err != nil {
		return err
	}

	aa.signer = jws.NewSigner(rsaSigner)
	pubjwk := aa.privjwk.RsaPublicKey
	for _, s := range aa.signer.Signers {
		if err := s.PublicHeaders().Set("jwk", pubjwk); err != nil {
			return err
		}
	}

	res, err := http.Get(aa.directoryURL)
	if err != nil {
		return err
	}
	if err := aa.updateNonce(res); err != nil {
		return err
	}

	if res.StatusCode > 299 {
		return newACMEError(res)
	}

	if err := json.NewDecoder(res.Body).Decode(&aa.directory); err != nil {
		return err
	}
	defer res.Body.Close()

	aa.initialized = true
	return nil
}

func (aa *AcmeAgent) sign(payload []byte) ([]byte, error) {
	msg, err := aa.signer.Sign(payload)
	if err != nil {
		return nil, err
	}
	return jws.JSONSerialize{}.Serialize(msg)
}

func (aa *AcmeAgent) updateNonce(res *http.Response) error {
	nonce := res.Header.Get("Replay-Nonce")
	if nonce == "" {
		return errors.New("header 'Replay-Nonce' not found")
	}

	for _, signer := range aa.signer.Signers {
		if err := signer.ProtectedHeaders().Set("nonce", nonce); err != nil {
			return err
		}
	}
	return nil
}

func (aa AcmeAgent) buildKeyAuthorization(token string) (string, error) {
	thumbprint, err := aa.privjwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	buf := bytes.Buffer{}
	buf.WriteString(token)
	buf.WriteByte('.')
	buf.WriteString(base64.RawURLEncoding.EncodeToString(thumbprint))
	return buf.String(), nil
}

func findLinkByName(res *http.Response, name string) (*link.Link, error) {
	for _, hdr := range res.Header[http.CanonicalHeaderKey("Link")] {
		links, err := link.Parse(hdr)
		if err != nil {
			return nil, err
		}

		for _, l := range links {
			if l.Rel == name {
				return &l, nil
			}
		}
	}
	return nil, errors.New("no link with name '" + name + "' found")
}

func findTOS(res *http.Response) (*link.Link, error) {
	return findLinkByName(res, "terms-of-service")
}

func (aa *AcmeAgent) sendRegistrationRequest(req RegistrationRequest) (*Account, error) {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.sendRegistrationRequest")
		defer g.End()
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	signed, err := aa.sign(payload)
	if err != nil {
		return nil, err
	}

	res, err := http.Post(aa.directory.NewReg, joseContentType, bytes.NewReader(signed))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if err := aa.updateNonce(res); err != nil {
		return nil, err
	}

	if res.StatusCode > 299 {
		return nil, newACMEError(res)
	}

	tosLink, err := findTOS(res)
	if err != nil {
		return nil, err
	}

	acct := Account{
		URL: res.Header.Get("Location"),
		TOS: tosLink.URI,
	}
	return &acct, nil
}

func (aa *AcmeAgent) sendUpdateRegistrationRequest(u string, req UpdateRegistrationRequest) error {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.sendUpdateRegistrationRequest")
		defer g.End()
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}

	signed, err := aa.sign(payload)
	if err != nil {
		return err
	}

	res, err := http.Post(u, joseContentType, bytes.NewReader(signed))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if err := aa.updateNonce(res); err != nil {
		return err
	}

	if res.StatusCode > 299 {
		return newACMEError(res)
	}

	return nil
}

func (aa *AcmeAgent) Register(email string) error {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.Register (%s)", email)
		defer g.End()
	}

	if err := aa.initialize(); err != nil {
		return err
	}

	var acct *Account
	err := aa.store.LoadAccount(acct)
	if err != nil {
		req := RegistrationRequest{
			Contact: []string{"mailto:" + email},
		}

		acct, err = aa.sendRegistrationRequest(req)
		if err != nil {
			return err
		}

		if err := aa.store.SaveAccount(acct); err != nil {
			return err
		}
	}

	if !acct.AgreedTOS.IsZero() {
		return nil
	}

	privjwk, err := aa.store.LoadKey()
	if err != nil {
		return err
	}

	upreq := UpdateRegistrationRequest{
		Contact:   []string{"mailto:" + email},
		Agreement: acct.TOS,
		Key:       privjwk.RsaPublicKey,
	}

	if err := aa.sendUpdateRegistrationRequest(acct.URL, upreq); err != nil {
		return err
	}

	acct.AgreedTOS = time.Now()
	if err := aa.store.SaveAccount(acct); err != nil {
		return err
	}

	return nil
}

type IdentifierAuthorizationContext struct {
	Domain string
}

func (aa *AcmeAgent) AuthorizeForDomain(domain string) error {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.AuthorizeForDomain (%s)", domain)
		defer g.End()
	}

	if err := aa.initialize(); err != nil {
		return err
	}

	ctx := IdentifierAuthorizationContext{
		Domain: domain,
	}

	authz, err := aa.sendAuthorizationRequest(&ctx)
	if err != nil {
		return err
	}

	if pdebug.Enabled {
		pdebug.Printf("sendAuthorizationRequest response: %#v", authz)
	}

	// TODO check authz status
	if err := aa.completeChallenges(&ctx, authz); err != nil {
		return err
	}

	return nil
}

func (aa *AcmeAgent) sendAuthorizationRequest(ctx *IdentifierAuthorizationContext) (*Authorization, error) {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.sendAuthorizationRequest")
		defer g.End()
	}

	req := AuthorizationRequest{
		Identifier: Identifier{
			Type:  "dns",
			Value: ctx.Domain,
		},
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	signed, err := aa.sign(payload)
	if err != nil {
		return nil, err
	}

	res, err := http.Post(aa.directory.NewAuthz, joseContentType, bytes.NewReader(signed))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if err := aa.updateNonce(res); err != nil {
		return nil, err
	}

	if res.StatusCode > 299 {
		return nil, newACMEError(res)
	}

	authzres := Authorization{
		URL: res.Header.Get("Location"),
	}
	if err := json.NewDecoder(res.Body).Decode(&authzres); err != nil {
		return nil, err
	}
	return &authzres, nil
}

func getChallengeStatus(u string, c *Challenge) error {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.getChallengeStatus (%s)", u)
		defer g.End()
	}

	res, err := http.Get(u)
	if err != nil {
		return err
	}

	if res.StatusCode > 299 {
		return newACMEError(res)
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(c)
}

func (aa *AcmeAgent) respondChallengeCompleted(challenge Challenge) error {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.respondChallengeCompleted")
		defer g.End()
	}

	keyauthz, err := aa.buildKeyAuthorization(challenge.Token)
	if err != nil {
		return err
	}
	req := ChallengeCompletionRequest{
		Resource:         "challenge",
		Type:             challenge.Type,
		Token:            challenge.Token,
		KeyAuthorization: keyauthz,
	}
	buf, err := json.Marshal(req)
	if err != nil {
		return err
	}
	signed, err := aa.sign(buf)
	if err != nil {
		return err
	}

	res, err := http.Post(challenge.URI, joseContentType, bytes.NewReader(signed))
	if err != nil {
		return err
	}
	if err := aa.updateNonce(res); err != nil {
		return err
	}

	var cret Challenge
	if err := json.NewDecoder(res.Body).Decode(&cret); err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusAccepted {
		return cret.Error
	}
	return nil
}

func (aa *AcmeAgent) completeChallenges(ctx *IdentifierAuthorizationContext, authz *Authorization) error {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.completeChallenges")
		defer g.End()
	}

	// If combinations is empty, we must fulfill all of the challenges
	// Otherwise, just do the ones specified
	var challenges [][]Challenge
	switch l := len(authz.Combinations); l {
	case 0:
		challenges = [][]Challenge{authz.Challenges}
	default:
		challenges = make([][]Challenge, l)
		for i, combination := range authz.Combinations {
			challenges[i] = make([]Challenge, len(combination))
			for j, idx := range combination {
				challenges[i][j] = authz.Challenges[idx]
			}
		}
	}

OUTER:
	for i, challengeSet := range challenges {
		if pdebug.Enabled {
			pdebug.Printf("Attempting challenge set #%d", i)
		}
		for _, challenge := range challengeSet {
			var cc ChallengeCompleter
			switch challenge.Type {
			case DNSChallenge:
				cc = aa.dnscc
			case HTTPChallenge:
				cc = aa.httpcc
			case TLSSNIChallenge:
				cc = aa.tlssnicc
			default:
				if pdebug.Enabled {
					pdebug.Printf("Challenge '%s' cannot be handled", challenge.Type)
				}
				// Taken care after this switch
			}

			if cc == nil {
				// oops, no can do. try next set
				continue OUTER
			}

			if pdebug.Enabled {
				pdebug.Printf("Attempting to complete challenge '%s'", challenge.Type)
			}

			keyauthz, err := aa.buildKeyAuthorization(challenge.Token)
			if err != nil {
				if pdebug.Enabled {
					pdebug.Printf("Failed to build key authorization: %s", err)
				}
				continue OUTER
			}

			if err := cc.Complete(ctx.Domain, keyauthz); err != nil {
				if pdebug.Enabled {
					pdebug.Printf("Failed to complete challenge '%s': %s", challenge.Type, err)
				}
				continue OUTER
			}
			defer cc.Cleanup(ctx.Domain, keyauthz)

			if pdebug.Enabled {
				pdebug.Printf("Successfully completed challenge '%s'", challenge.Type)
			}
		}
		// Congratulations! Once you go there, that means
		// we completed this challenge set!
		if pdebug.Enabled {
			pdebug.Printf("Successfully completed challenge set #%d", i)
		}

		// Now let the server know that we have completed
		// the specified tasks...
		for _, challenge := range challengeSet {
			if err := aa.respondChallengeCompleted(challenge); err != nil {
				return err
			}
		}

		// ...And wait for the server to acknowledge it
		if err := aa.WaitChallengeValidation(challengeSet); err != nil {
			return err
		}
		return nil
	}
	return errors.New("none of the challenge sets could be completed")
}

func (aa *AcmeAgent) WaitChallengeValidation(challenges []Challenge) error {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.WaitChallengeValidation")
		defer g.End()
	}

	var wg sync.WaitGroup
	results := make([]error, len(challenges))
	for i, challenge := range challenges {
		wg.Add(1)
		go func(wg *sync.WaitGroup, ch Challenge, err *error) {
			timeout := time.After(5 * time.Minute)
			ticker := time.Tick(5 * time.Second)

			defer wg.Done()
			for {
				select {
				case <-timeout:
					*err = errors.New("timeout reached")
				case <-ticker:
					var st Challenge
					if *err = getChallengeStatus(ch.URI, &st); *err != nil {
						return
					}

					if pdebug.Enabled {
						buf, _ := json.MarshalIndent(st, "", "  ")
						pdebug.Printf("Challenge status (%s):", ch.URI)
						pdebug.Printf("%s", buf)
					}

					switch st.Status {
					case "pending":
						continue
					case "invalid":
						*err = errors.New("challenge validation failed")
						return
					case "valid":
						return
					}
				}
			}
		}(&wg, challenge, &results[i])
	}

	wg.Wait()
	for _, err := range results {
		if err != nil {
			return err
		}
	}

	return nil
}

type IssueCertificateContext struct {
	CommonName string
	Domains    []string
	Renew      bool
}

func (aa *AcmeAgent) IssueCertificate(cn string, domains []string, renew bool) error {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.IssueCertificate (%s)", cn)
		defer g.End()
	}

	if err := aa.initialize(); err != nil {
		return err
	}

	ctx := IssueCertificateContext{
		CommonName: cn,
		Domains:    domains,
		Renew:      renew,
	}

	if cert, err := aa.store.LoadCert(ctx.CommonName); err == nil && time.Now().Before(cert.NotAfter.AddDate(0, -1, 0)) {
		if pdebug.Enabled {
			pdebug.Printf("Certificate is valid until %s, aborting", cert.NotAfter.Format(time.RFC3339))
		}
		return nil
	}

	if pdebug.Enabled {
		pdebug.Printf("Issuing new certificiate")
	}

	privjwk, err := aa.store.LoadCertKey(ctx.CommonName)
	if err != nil {
		// No certificate key available, need to create a new one
		certkey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return err
		}

		privjwk, err = jwk.NewRsaPrivateKey(certkey)
		if err != nil {
			return err
		}

		if err := aa.store.SaveCertKey(ctx.CommonName, privjwk); err != nil {
			return err
		}
	}

	csr := x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		Subject: pkix.Name{
			CommonName: ctx.CommonName,
		},
		DNSNames: append([]string{ctx.CommonName}, ctx.Domains...),
	}

	privkey, err := privjwk.PrivateKey()
	if err != nil {
		return err
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &csr, privkey)
	if err != nil {
		return err
	}

	certURL, err := aa.sendIssueCertificateRequest(&ctx, der)
	if err != nil {
		return err
	}

	if pdebug.Enabled {
		pdebug.Printf("Fetching certs from %s", certURL)
	}

	issuerCert, myCert, err := aa.WaitForCertificates(&ctx, certURL)
	if err != nil {
		return err
	}

	if err := aa.store.SaveCert(ctx.CommonName, issuerCert, myCert); err != nil {
		return err
	}
	return nil
}

func (aa *AcmeAgent) sendIssueCertificateRequest(ctx *IssueCertificateContext, der []byte) (certURL string, err error) {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.sendIssueCertificateRequest").BindError(&err)
		defer g.End()
	}

	req := CertificateRequest{
		CSR: base64.RawURLEncoding.EncodeToString(der),
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	signed, err := aa.sign(payload)
	if err != nil {
		return "", err
	}

	httpreq, err := http.NewRequest("POST", aa.directory.NewCert, bytes.NewReader(signed))
	httpreq.Header.Set("Content-Type", joseContentType)
	httpreq.Header.Set("Accept", "application/pkix-cert")

	res, err := http.DefaultClient.Do(httpreq)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if err := aa.updateNonce(res); err != nil {
		return "", err
	}

	if res.StatusCode > 299 {
		return "", newACMEError(res)
	}

	return res.Header.Get("Location"), nil
}

func (aa *AcmeAgent) WaitForCertificates(ctx *IssueCertificateContext, u string) (issuerCert *x509.Certificate, myCert *x509.Certificate, err error) {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.WaitForCertificates").BindError(&err)
		defer g.End()
	}
	timeout := time.After(3 * time.Minute)
	ticker := time.Tick(5 * time.Second)

	var certres *http.Response
	for {
		select {
		case <-timeout:
			return nil, nil, errors.New("timeout reached")
		case <-ticker:
			httpreq, err := http.NewRequest("GET", u, nil)
			httpreq.Header.Set("Accept", "application/pkix-cert")

			res, err := http.DefaultClient.Do(httpreq)
			if err != nil {
				return nil, nil, err
			}

			if res.StatusCode > 299 {
				return nil, nil, newACMEError(res)
			}

			switch res.StatusCode {
			case http.StatusAccepted:
				// Still creating the certificate...
				if pdebug.Enabled {
					pdebug.Printf("Certificate not ready yet...")
				}
				continue
			case http.StatusOK:
				// Ooooh, yeah!
				certres = res
				goto GetCert
			default:
				// We got a problem
				return nil, nil, errors.New("invalid response: " + res.Status)
			}
		}
	}

GetCert:
	buf, err := ioutil.ReadAll(certres.Body)
	if err != nil {
		return nil, nil, err
	}

	// This buffer contains my cert
	myCert, err = x509.ParseCertificate(buf)
	if err != nil {
		return nil, nil, err
	}

	// Now look for the issuer cert
	certlink, err := findLinkByName(certres, "up")
	if err != nil {
		return nil, nil, err
	}

	uparsed, err := url.Parse(u)
	if err != nil {
		return nil, nil, err
	}
	uparsed, err = uparsed.Parse(certlink.URI)
	if err != nil {
		return nil, nil, err
	}

	if pdebug.Enabled {
		pdebug.Printf("Next, fetching issuer certificate from %s", uparsed.String())
	}

	httpreq, err := http.NewRequest("GET", uparsed.String(), nil)
	httpreq.Header.Set("Accept", "application/pkix-cert")
	issuerres, err := http.DefaultClient.Do(httpreq)
	if err != nil {
		return nil, nil, err
	}

	buf, err = ioutil.ReadAll(issuerres.Body)
	if err != nil {
		return nil, nil, err
	}

	// This buffer contains issuer cert
	issuerCert, err = x509.ParseCertificate(buf)
	if err != nil {
		return nil, nil, err
	}

	if pdebug.Enabled {
		pdebug.Printf("All done, returning certs")
	}

	return issuerCert, myCert, nil
}

func (aa *AcmeAgent) UploadCertificate(domain string) (err error) {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.UploadCertificate (%s)", domain).BindError(&err)
		defer g.End()
	}

	if aa.uploader == nil {
		return errors.New("uploader not configured")
	}

	certs := make([]*x509.Certificate, 2)

	cert, err := aa.store.LoadCert(domain)
	if err != nil {
		return err
	}
	certs[0] = cert

	cert, err = aa.store.LoadCertIssuer(domain)
	if err != nil {
		return err
	}
	certs[1] = cert

	certjwk, err := aa.store.LoadCertKey(domain)
	if err != nil {
		return err
	}
	certkey, err := certjwk.PrivateKey()
	if err != nil {
		return err
	}

	// domain names contain periods and such, so replace those with a dash
	buf := bytes.Buffer{}
	for _, r := range domain {
		if r == '.' {
			r = '-'
		}
		buf.WriteRune(r)
	}
	return aa.uploader.Upload(buf.String(), certs, certkey)
}
