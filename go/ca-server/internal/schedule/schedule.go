// Package schedule manages passwordless-certificate schedules — clients request
// time-window rules that let them issue SSH certs without TOTP during approved
// periods.  Each mTLS client may have one pending request at a time; after
// approval the rules take effect immediately and the client can submit a new
// request.
package schedule

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---- data model ------------------------------------------------------------

// Rule describes one passwordless time window.
type Rule struct {
	Days      []int  `json:"days"`       // 0=Sun..6=Sat; nil or empty = every day
	StartTime string `json:"start_time"` // "HH:MM"
	EndTime   string `json:"end_time"`   // "HH:MM"
	MaxCount  int    `json:"max_count"`  // max certs in window
	Group     string `json:"group"`      // TOTP group to bind
	UsedCount int    `json:"used_count"` // run-time counter (reset daily)
	LastReset string `json:"last_reset"` // date-string "2006-01-02"
}

// Request is a client-submitted passwordless-schedule application.
type Request struct {
	ClientName string `json:"client_name"` // mTLS cert CN
	GrantedTo  string `json:"granted_to"`  // mTLS cert OU
	Status     string `json:"status"`      // pending | approved | rejected
	Rules      []Rule `json:"rules"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// ClientSchedules holds all approved rules for one mTLS client.
type ClientSchedules struct {
	ClientName string `json:"client_name"`
	Rules      []Rule `json:"rules"`
}

// ---- file paths ------------------------------------------------------------

func requestsPath(dataDir string) string  { return filepath.Join(dataDir, "schedule-requests.json") }
func approvedPath(dataDir string) string  { return filepath.Join(dataDir, "schedules-approved.json") }

// ---- persistence -----------------------------------------------------------

var mu sync.Mutex

func loadRequests(dataDir string) (map[string]*Request, error) {
	path := requestsPath(dataDir)
	m := make(map[string]*Request)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

func saveRequests(dataDir string, m map[string]*Request) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(requestsPath(dataDir), append(data, '\n'), 0644)
}

func loadApproved(dataDir string) (map[string]*ClientSchedules, error) {
	path := approvedPath(dataDir)
	m := make(map[string]*ClientSchedules)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

func saveApproved(dataDir string, m map[string]*ClientSchedules) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(approvedPath(dataDir), append(data, '\n'), 0644)
}

// ---- operations ------------------------------------------------------------

// SubmitRequest creates or replaces a pending request for a client.  Only one
// pending request per client is allowed; submitting a new one replaces the old.
func SubmitRequest(dataDir string, clientName, grantedTo string, rules []Rule) error {
	mu.Lock()
	defer mu.Unlock()

	reqs, err := loadRequests(dataDir)
	if err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	req := &Request{
		ClientName: clientName,
		GrantedTo:  grantedTo,
		Status:     "pending",
		Rules:      rules,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	// Each client can only have one request.  Replace the previous one.
	reqs[clientName] = req
	return saveRequests(dataDir, reqs)
}

// GetRequest returns a client's current request (pending / approved / rejected).
func GetRequest(dataDir, clientName string) (*Request, error) {
	mu.Lock()
	defer mu.Unlock()

	reqs, err := loadRequests(dataDir)
	if err != nil {
		return nil, err
	}
	r, ok := reqs[clientName]
	if !ok {
		return nil, nil
	}
	return r, nil
}

// ListRequests returns all requests, sorted by client name.
func ListRequests(dataDir string) ([]*Request, error) {
	mu.Lock()
	defer mu.Unlock()

	reqs, err := loadRequests(dataDir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(reqs))
	for n := range reqs {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]*Request, 0, len(names))
	for _, n := range names {
		out = append(out, reqs[n])
	}
	return out, nil
}

// ApproveRequest moves a pending request to approved state and copies its
// rules into the approved-schedules file (overwriting any prior rules for
// that client).
func ApproveRequest(dataDir, clientName string) error {
	mu.Lock()
	defer mu.Unlock()

	reqs, err := loadRequests(dataDir)
	if err != nil {
		return err
	}
	r, ok := reqs[clientName]
	if !ok {
		return fmt.Errorf("no request for client %q", clientName)
	}
	if r.Status != "pending" {
		return fmt.Errorf("request for %q is not pending (status=%s)", clientName, r.Status)
	}

	r.Status = "approved"
	r.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	reqs[clientName] = r
	if err := saveRequests(dataDir, reqs); err != nil {
		return err
	}

	// Copy rules into approved-schedules
	app, err := loadApproved(dataDir)
	if err != nil {
		return err
	}
	app[clientName] = &ClientSchedules{
		ClientName: clientName,
		Rules:      r.Rules,
	}
	return saveApproved(dataDir, app)
}

// RejectRequest marks a pending request as rejected.
func RejectRequest(dataDir, clientName string) error {
	mu.Lock()
	defer mu.Unlock()

	reqs, err := loadRequests(dataDir)
	if err != nil {
		return err
	}
	r, ok := reqs[clientName]
	if !ok {
		return fmt.Errorf("no request for client %q", clientName)
	}
	r.Status = "rejected"
	r.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	reqs[clientName] = r
	return saveRequests(dataDir, reqs)
}

// ---- rule matching ---------------------------------------------------------

// MatchTime reports whether the given rule is active right now.
func (r *Rule) MatchTime(now time.Time) bool {
	// Day-of-week check
	if len(r.Days) > 0 {
		wd := now.Weekday() // Sunday=0
		found := false
		for _, d := range r.Days {
			if d == int(wd) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Time window check
	return inTimeRange(now, r.StartTime, r.EndTime)
}

// inTimeRange returns true when now's HH:MM falls within [start, end).
func inTimeRange(now time.Time, start, end string) bool {
	t := now.Format("15:04")
	return t >= start && t < end
}

// ---- runtime lookup --------------------------------------------------------

// MatchClient checks whether a client has an active passwordless rule right
// now.  Returns the matching rule (or nil), its index, and whether the count
// is within the limit.
func MatchClient(dataDir, clientName string, now time.Time) (*Rule, *ClientSchedules, int, error) {
	mu.Lock()
	defer mu.Unlock()

	app, err := loadApproved(dataDir)
	if err != nil {
		return nil, nil, 0, err
	}
	cs, ok := app[clientName]
	if !ok || len(cs.Rules) == 0 {
		return nil, nil, 0, nil
	}

	for i, rule := range cs.Rules {
		if !rule.MatchTime(now) {
			continue
		}
		// Reset daily counter if date changed
		today := now.Format("2006-01-02")
		if rule.LastReset != today {
			cs.Rules[i].UsedCount = 0
			cs.Rules[i].LastReset = today
			// Save immediately
			app[clientName] = cs
			if saveErr := saveApproved(dataDir, app); saveErr != nil {
				return nil, nil, 0, saveErr
			}
		}
		if cs.Rules[i].UsedCount >= cs.Rules[i].MaxCount {
			return &cs.Rules[i], cs, i, fmt.Errorf("schedule limit reached (%d/%d)", cs.Rules[i].UsedCount, cs.Rules[i].MaxCount)
		}
		return &cs.Rules[i], cs, i, nil
	}
	return nil, nil, 0, nil
}

// IncrementUsed bumps the UsedCount for a matched rule and persists.
func IncrementUsed(dataDir string, cs *ClientSchedules, ruleIdx int) error {
	mu.Lock()
	defer mu.Unlock()

	app, err := loadApproved(dataDir)
	if err != nil {
		return err
	}
	if entry, ok := app[cs.ClientName]; ok {
		if ruleIdx < len(entry.Rules) {
			entry.Rules[ruleIdx].UsedCount++
			entry.Rules[ruleIdx].LastReset = time.Now().Format("2006-01-02")
		}
	}
	return saveApproved(dataDir, app)
}

// ---- validation ------------------------------------------------------------

// ValidateRules checks each rule for basic correctness.
func ValidateRules(rules []Rule) error {
	if len(rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}
	for i, r := range rules {
		if r.MaxCount <= 0 {
			return fmt.Errorf("rule %d: max_count must be > 0", i)
		}
		if strings.TrimSpace(r.Group) == "" {
			return fmt.Errorf("rule %d: group is required", i)
		}
		if r.StartTime == "" || r.EndTime == "" {
			return fmt.Errorf("rule %d: start_time and end_time are required", i)
		}
		if r.StartTime >= r.EndTime {
			return fmt.Errorf("rule %d: start_time must be before end_time", i)
		}
	}
	return nil
}
