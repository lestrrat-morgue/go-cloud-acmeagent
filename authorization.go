package acmeagent

import "time"

func (a Authorization) ExpTime() time.Time {
	expires, _ := time.Parse(time.RFC3339, a.Expires)
	return expires
}

func (a Authorization) IsExpired() bool {
	return a.ExpTime().Before(time.Now())
}
