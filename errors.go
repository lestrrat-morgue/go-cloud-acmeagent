package acmeagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func (e *ACMEError) Error() string {
	return fmt.Sprintf(
		"acme error(%d): type: %s detail: %s",
		e.StatusCode,
		e.Type,
		e.Detail,
	)
}

func newACMEError(resp *http.Response) error {
	e := &ACMEError{
		StatusCode: resp.StatusCode,
	}
	if err := json.NewDecoder(resp.Body).Decode(e); err != nil {
		return errors.New("failed to decode acme error")
	}
	return e
}
