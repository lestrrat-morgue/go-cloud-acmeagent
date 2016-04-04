package acmeagent

import "encoding/json"

func (r AuthorizationRequest) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"identifier": r.Identifier,
		"resource":   "new-authz",
	}
	return json.Marshal(m)
}
