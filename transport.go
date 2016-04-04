package acmeagent

import "encoding/json"

func (r AuthorizationRequest) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"identifier": r.Identifier,
		"resource":   "new-authz",
	}
	return json.Marshal(m)
}

func (r CertificateRequest) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"csr":      r.CSR,
		"resource": "new-cert",
	}
	return json.Marshal(m)
}

func (r RegistrationRequest) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"agreement":      r.Agreement,
		"authorizations": r.Authorizations,
		"certificates":   r.Certificates,
		"contact":        r.Contact,
		"resource":       "new-reg",
	}
	return json.Marshal(m)
}

func (r UpdateRegistrationRequest) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"contact":  r.Contact,
		"resource": "reg",
	}

	if key := r.Key; key != nil {
		m["key"] = key
	}

	if v := r.Agreement; v != "" {
		m["agreement"] = v
	}

	return json.Marshal(m)
}
