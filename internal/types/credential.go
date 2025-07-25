package types

import "time"

type Credential struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	URL      string   `json:"url"`
	URLs     []string `json:"urls,omitempty"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Notes    string   `json:"notes,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

type AuditContext struct {
	Credentials []Credential `json:"credentials"`
	Timestamp   time.Time    `json:"timestamp"`
}
