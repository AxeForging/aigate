package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AllowOnceTTL bounds how long an allow-once grant waits to be used.
const AllowOnceTTL = 10 * time.Minute

// CallID identifies a call for allow-once: same tool, target and input.
func CallID(call Call) string {
	sum := sha256.Sum256([]byte(call.Tool + "\x00" + call.Target + "\x00" + call.Input))
	return hex.EncodeToString(sum[:6])
}

type allowOnceGrant struct {
	Expires time.Time `json:"expires"`
	Reason  string    `json:"reason,omitempty"`
}

// AllowOnceStore keeps single-use grants in ~/.aigate (hidden inside the
// sandbox, so an agent can't grant itself anything).
type AllowOnceStore struct {
	Path string
	mu   sync.Mutex
}

func (s *AllowOnceStore) load() map[string]allowOnceGrant {
	grants := map[string]allowOnceGrant{}
	if b, err := os.ReadFile(s.Path); err == nil {
		_ = json.Unmarshal(b, &grants)
	}
	now := time.Now()
	for id, g := range grants {
		if now.After(g.Expires) {
			delete(grants, id)
		}
	}
	return grants
}

func (s *AllowOnceStore) save(grants map[string]allowOnceGrant) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(grants)
	return os.WriteFile(s.Path, b, 0o600)
}

// Grant allows the call with this id once, within AllowOnceTTL.
func (s *AllowOnceStore) Grant(id, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	grants := s.load()
	grants[id] = allowOnceGrant{Expires: time.Now().Add(AllowOnceTTL), Reason: reason}
	return s.save(grants)
}

// Consume reports whether id was granted and removes the grant.
func (s *AllowOnceStore) Consume(id string) (reason string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grants := s.load()
	g, ok := grants[id]
	if !ok {
		return "", false
	}
	delete(grants, id)
	_ = s.save(grants)
	return g.Reason, true
}
