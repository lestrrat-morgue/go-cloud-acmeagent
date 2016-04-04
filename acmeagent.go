package acmeagent

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/lestrrat/go-pdebug"
)

// New creates a new AcmeAgent.
func New(opts AgentOptions) (*AcmeAgent, error) {
	agent := AcmeAgent{
		dnscc:        opts.DNSCompleter,
		httpcc:       opts.HTTPCompleter,
		tlssnicc:     opts.TLSSNICompleter,
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
func (a *AcmeAgent) initialize() (err error) {
	a.initLock.Lock()
	defer a.initLock.Unlock()

	if a.initialized {
		return nil
	}

	a.privjwk, err = a.store.LoadKey()
	if err != nil {
		return err
	}
	a.privkey, err = a.privjwk.PrivateKey()
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}

	rsaSigner, err := jws.NewRsaSign(jwa.RS256, a.privkey)
	if err != nil {
		return err
	}

	a.signer = jws.NewSigner(rsaSigner)
	pubjwk := a.privjwk.RsaPublicKey
	for _, s := range a.signer.Signers {
		if err := s.PublicHeaders().Set("jwk", pubjwk); err != nil {
			return err
		}
	}

	res, err := http.Get(a.directoryURL)
	if err != nil {
		return err
	}
	if err := a.updateNonce(res); err != nil {
		return err
	}

	if res.StatusCode > 299 {
		return newACMEError(res)
	}

	if err := json.NewDecoder(res.Body).Decode(&a.directory); err != nil {
		return err
	}
	defer res.Body.Close()

	a.initialized = true
	return nil
}

func (a *AcmeAgent) sign(payload []byte) ([]byte, error) {
	msg, err := a.signer.Sign(payload)
	if err != nil {
		return nil, err
	}
	return jws.JSONSerialize{}.Serialize(msg)
}

func (a *AcmeAgent) updateNonce(res *http.Response) error {
	nonce := res.Header.Get("Replay-Nonce")
	if nonce == "" {
		return errors.New("header 'Replay-Nonce' not found")
	}

	for _, signer := range a.signer.Signers {
		if err := signer.ProtectedHeaders().Set("nonce", nonce); err != nil {
			return err
		}
	}
	return nil
}

func (a AcmeAgent) buildKeyAuthorization(token string) (string, error) {
	thumbprint, err := a.privjwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	buf := bytes.Buffer{}
	buf.WriteString(token)
	buf.WriteByte('.')
	buf.WriteString(base64.RawURLEncoding.EncodeToString(thumbprint))
	return buf.String(), nil
}

type IdentifierAuthorizationContext struct {
	Domain string
}

func (a *AcmeAgent) AuthorizeForDomain(domain string) error {
	if pdebug.Enabled {
		g := pdebug.Marker("AcmeAgent.AuthorizeForDomain (%s)", domain)
		defer g.End()
	}

	if err := a.initialize(); err != nil {
		return err
	}

	ctx := IdentifierAuthorizationContext{
		Domain: domain,
	}

	authz, err := a.sendAuthorizationRequest(&ctx)
	if err != nil {
		return err
	}

	// TODO check authz status
	if err := a.completeChallenges(&ctx, authz); err != nil {
		return err
	}

	return nil
}

func (a *AcmeAgent) sendAuthorizationRequest(ctx *IdentifierAuthorizationContext) (*Authorization, error) {
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

	signed, err := a.sign(payload)
	if err != nil {
		return nil, err
	}

	res, err := http.Post(a.directory.NewAuthz, joseContentType, bytes.NewReader(signed))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if err := a.updateNonce(res); err != nil {
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
	for _, challengeSet := range challenges {
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
				// Taken care after this switch
			}

			if cc == nil {
				// oops, no can do. try next set
				continue OUTER
			}

			keyauthz, err := aa.buildKeyAuthorization(challenge.Token)
			if err != nil {
				continue OUTER
			}

			if err := cc.Complete(ctx.Domain, keyauthz); err != nil {
				continue OUTER
			}
		}
		// Congratulations! Once you go there, that means
		// we completed this challenge set!

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
	var results []error
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
					if *err = getChallengeStatus(ch.URI, &st); err != nil {
						return
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
