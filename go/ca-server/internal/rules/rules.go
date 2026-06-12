// Package rules implements the V4.0 rule system.
//
// Two layers:
//   Config layer  — user-editable rule definitions, may conflict
//   Exec layer    — compiled from config layer, no conflicts
//
// Rules are per-target.  Each target has issue_rules (cert issuance) and
// judge_rules (sudo).  Each rule can specify clients (mTLS CN list),
// priority, time windows, and mode / sudo flag.
package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ---- data model: config layer ---------------------------------------------

// Mode for issue rules.
type Mode string

const (
	ModePasswordless Mode = "passwordless"
	ModeTOTP         Mode = "totp"
	ModeDeny         Mode = "deny"
)

// TimeWindow describes one non-overlapping time fragment.
type TimeWindow struct {
	Weekdays []int  `json:"weekdays"` // 0=Sun..6=Sat, empty=every day
	Start    string `json:"start"`    // "HH:MM"
	End      string `json:"end"`      // "HH:MM"
}

// IssueConfig controls cert issuance for one rule.
type IssueConfig struct {
	Mode     Mode `json:"mode"`               // passwordless | totp | deny
	MaxCount int  `json:"max_count,omitempty"` // 0 = unlimited
}

// JudgeConfig controls sudo for one rule.
type JudgeConfig struct {
	SUDOAllowed bool `json:"sudo_allowed"`
}

// Rule is one config-layer rule.
type Rule struct {
	ID       string     `json:"id"`
	Priority int        `json:"priority"`           // smaller = higher priority
	Clients  []string   `json:"clients,omitempty"`  // nil/empty = all
	Windows  []TimeWindow `json:"windows"`
	Issue    *IssueConfig `json:"issue,omitempty"`
	Judge    *JudgeConfig `json:"judge,omitempty"`
}

// RulesFile is the on-disk rules configuration for one target.
type RulesFile struct {
	Rules []Rule `json:"rules"`
}

// ---- data model: exec layer -----------------------------------------------

// ExecSegment is one time segment from the compiled exec layer.
type ExecSegment struct {
	Weekday      int    `json:"weekday"`        // 0=Sun..6=Sat
	Start        string `json:"start"`          // "HH:MM"
	End          string `json:"end"`            // "HH:MM"
	IssueMode    Mode   `json:"issue_mode"`     // passwordless | totp | deny
	SUDOAllowed  bool   `json:"sudo_allowed"`
}

// ExecLayer is the compiled output for one target+group.
// Segments are sorted by (weekday, start) and non-overlapping for a given
// weekday.  Multiple weekdays are stored as separate segments.
type ExecLayer struct {
	Target   string       `json:"target"`
	Group    string       `json:"group"`
	Segments []ExecSegment `json:"segments"`
}

// ---- persistence ----------------------------------------------------------

var mu sync.Mutex

const rulesDir = "rules"

func rulesPath(dataDir, target, group string) string {
	return filepath.Join(dataDir, "targets", target, "groups", group, "rules.json")
}

func execPath(dataDir, target, group string) string {
	return filepath.Join(dataDir, "targets", target, "groups", group, "exec-segments.json")
}

// LoadRules reads the config-layer rules for a target+group.
func LoadRules(dataDir, target, group string) (*RulesFile, error) {
	path := rulesPath(dataDir, target, group)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &RulesFile{}, nil
		}
		return nil, err
	}
	var rf RulesFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parse rules %s: %w", path, err)
	}
	return &rf, nil
}

// SaveRules persists config-layer rules.
func SaveRules(dataDir, target, group string, rf *RulesFile) error {
	mu.Lock()
	defer mu.Unlock()

	dir := filepath.Dir(rulesPath(dataDir, target, group))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rf, "", "  ")
	if err != nil {
		return err
	}
	path := rulesPath(dataDir, target, group)
	return os.WriteFile(path, append(data, '\n'), 0644)
}

// LoadExecLayer reads the compiled exec layer.
func LoadExecLayer(dataDir, target, group string) (*ExecLayer, error) {
	path := execPath(dataDir, target, group)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var el ExecLayer
	if err := json.Unmarshal(data, &el); err != nil {
		return nil, fmt.Errorf("parse exec layer %s: %w", path, err)
	}
	return &el, nil
}

// SaveExecLayer persists the compiled exec layer.
func SaveExecLayer(dataDir, target, group string, el *ExecLayer) error {
	dir := filepath.Dir(execPath(dataDir, target, group))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(el, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(execPath(dataDir, target, group), append(data, '\n'), 0644)
}

// ---- validation -----------------------------------------------------------

// ValidateRule checks one rule for basic correctness.
func ValidateRule(r Rule) error {
	if r.ID == "" {
		return fmt.Errorf("rule id is required")
	}
	if len(r.Windows) == 0 {
		return fmt.Errorf("at least one window is required")
	}
	for _, w := range r.Windows {
		if w.Start == "" || w.End == "" {
			return fmt.Errorf("window start and end are required")
		}
		if w.Start >= w.End {
			return fmt.Errorf("start must be before end (got %s >= %s)", w.Start, w.End)
		}
	}
	if r.Issue == nil && r.Judge == nil {
		return fmt.Errorf("at least one of issue or judge config is required")
	}
	if r.Issue != nil {
		switch r.Issue.Mode {
		case ModePasswordless, ModeTOTP, ModeDeny:
		default:
			return fmt.Errorf("invalid issue mode: %s", r.Issue.Mode)
		}
		if r.Issue.MaxCount < 0 {
			return fmt.Errorf("max_count must be >= 0")
		}
	}
	return nil
}

// ---- compile: config layer → exec layer -----------------------------------

// Compile merges multiple rules into a conflict-free exec layer.
//
// Algorithm:
//   1. Collect all rules with issue or judge config
//   2. Sort by priority ascending (lower = higher priority)
//   3. Same priority: preserve config order (later wins in conflict)
//   4. For each weekday: collect all time boundaries, split into minimal intervals
//   5. For each interval: determine final mode + sudo state by highest-priority matching rule
//   6. Merge adjacent segments with identical config
func Compile(rules []Rule) []ExecSegment {
	if len(rules) == 0 {
		return nil
	}
	var all []ExecSegment
	for wd := 0; wd <= 6; wd++ {
		segs := compileWeekday(rules, wd)
		all = append(all, segs...)
	}
	return all
}

// compileWeekday compiles segments for one weekday.
func compileWeekday(rules []Rule, wd int) []ExecSegment {
	type ruleWithIdx struct {
		rule  Rule
		index int
	}
	var active []ruleWithIdx
	for i, r := range rules {
		for _, w := range r.Windows {
			if dayMatch(w.Weekdays, wd) && w.Start < w.End {
				active = append(active, ruleWithIdx{r, i})
				break
			}
		}
	}
	if len(active) == 0 {
		return nil
	}

	// Sort by priority ascending, then by original index
	sort.SliceStable(active, func(i, j int) bool {
		if active[i].rule.Priority != active[j].rule.Priority {
			return active[i].rule.Priority < active[j].rule.Priority
		}
		return active[i].index < active[j].index
	})

	// Collect unique time boundaries
	boundaries := make(map[string]bool)
	boundaries["00:00"] = true
	boundaries["24:00"] = true
	for _, a := range active {
		for _, w := range a.rule.Windows {
			if dayMatch(w.Weekdays, wd) {
				boundaries[w.Start] = true
				boundaries[w.End] = true
			}
		}
	}
	var sorted []string
	for b := range boundaries {
		sorted = append(sorted, b)
	}
	sort.Strings(sorted)

	// For each consecutive boundary pair, determine the winning config
	var segments []ExecSegment
	for i := 0; i < len(sorted)-1; i++ {
		start := sorted[i]
		end := sorted[i+1]
		mid := midpoint(start)

		var bestIssue *IssueConfig
		var bestJudge *JudgeConfig
		for _, a := range active {
			for _, w := range a.rule.Windows {
				if !dayMatch(w.Weekdays, wd) {
					continue
				}
				if mid >= w.Start && mid < w.End {
					if a.rule.Issue != nil {
						bestIssue = a.rule.Issue
					}
					if a.rule.Judge != nil {
						bestJudge = a.rule.Judge
					}
				}
			}
		}

		seg := ExecSegment{
			Weekday: wd,
			Start:   start,
			End:     end,
		}
		if bestIssue != nil {
			seg.IssueMode = bestIssue.Mode
		}
		if bestJudge != nil {
			seg.SUDOAllowed = bestJudge.SUDOAllowed
		}
		segments = append(segments, seg)
	}

	// Merge adjacent segments with identical config
	if len(segments) <= 1 {
		return segments
	}
	merged := []ExecSegment{segments[0]}
	for i := 1; i < len(segments); i++ {
		last := &merged[len(merged)-1]
		if last.IssueMode == segments[i].IssueMode && last.SUDOAllowed == segments[i].SUDOAllowed {
			last.End = segments[i].End
		} else {
			merged = append(merged, segments[i])
		}
	}
	return merged
}

// midpoint returns the time halfway between a HH:MM string and the next minute.
func midpoint(t string) string {
	h, m := 0, 0
	fmt.Sscanf(t, "%d:%d", &h, &m)
	m++
	if m >= 60 {
		h++
		m = 0
	}
	if h >= 24 {
		h = 0
	}
	return fmt.Sprintf("%02d:%02d", h, m)
}

// ---- runtime queries ------------------------------------------------------

// CheckIssueResult is the result of checking issue rules for a client+time.
type CheckIssueResult struct {
	Mode     Mode
	MaxCount int
	RuleID   string
	Deny     bool
}

// CheckIssue determines the issue mode for a given client+time.
// Returns the effective mode based on rules priority and client matching.
func CheckIssue(dataDir, target, group, clientCN string, now time.Time) (*CheckIssueResult, error) {
	rf, err := LoadRules(dataDir, target, group)
	if err != nil {
		return nil, err
	}
	if rf == nil || len(rf.Rules) == 0 {
		return nil, nil
	}

	// Sort by priority descending (low first), then by config order
	// Same priority: use stable sort preserving original order
	type indexed struct {
		rule  Rule
		index int
	}
	var indexedRules []indexed
	for i, r := range rf.Rules {
		indexedRules = append(indexedRules, indexed{r, i})
	}
	sort.SliceStable(indexedRules, func(i, j int) bool {
		if indexedRules[i].rule.Priority != indexedRules[j].rule.Priority {
			return indexedRules[i].rule.Priority < indexedRules[j].rule.Priority // smaller first = higher prio
		}
		return indexedRules[i].index < indexedRules[j].index // same prio: earlier config wins
	})

	thisMin := now.Format("15:04")
	thisWD := int(now.Weekday())

	var best *Rule
	bestPrio := -1
	bestIndex := -1

	for _, ir := range indexedRules {
		r := ir.rule
		// Check if rule applies to this client
		if len(r.Clients) > 0 {
			match := false
			for _, c := range r.Clients {
				if c == clientCN {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		// Skip judge-only rules for issue checking
		if r.Issue == nil {
			continue
		}
		// Check windows
		matches := false
		for _, w := range r.Windows {
			if !dayMatch(w.Weekdays, thisWD) {
				continue
			}
			if thisMin >= w.Start && thisMin < w.End {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}

		// Higher priority = lower number
		if best == nil || r.Priority < bestPrio || (r.Priority == bestPrio && ir.index > bestIndex) {
			best = &r
			bestPrio = r.Priority
			bestIndex = ir.index
		}
	}

	if best == nil || best.Issue == nil {
		return nil, nil
	}

	return &CheckIssueResult{
		Mode:     best.Issue.Mode,
		MaxCount: best.Issue.MaxCount,
		RuleID:   best.ID,
		Deny:     best.Issue.Mode == ModeDeny,
	}, nil
}

// CheckJudge determines whether sudo is allowed for a given client+time.
func CheckJudge(dataDir, target, group, clientCN string, now time.Time) (bool, error) {
	rf, err := LoadRules(dataDir, target, group)
	if err != nil {
		return false, err
	}
	if rf == nil {
		return false, nil
	}

	// Same priority sort as CheckIssue
	type indexed struct {
		rule  Rule
		index int
	}
	var indexedRules []indexed
	for i, r := range rf.Rules {
		if r.Judge == nil {
			continue
		}
		indexedRules = append(indexedRules, indexed{r, i})
	}
	sort.SliceStable(indexedRules, func(i, j int) bool {
		if indexedRules[i].rule.Priority != indexedRules[j].rule.Priority {
			return indexedRules[i].rule.Priority < indexedRules[j].rule.Priority
		}
		return indexedRules[i].index < indexedRules[j].index
	})

	thisMin := now.Format("15:04")
	thisWD := int(now.Weekday())

	var best *Rule
	bestPrio := -1
	bestIndex := -1

	for _, ir := range indexedRules {
		r := ir.rule
		if len(r.Clients) > 0 {
			match := false
			for _, c := range r.Clients {
				if c == clientCN {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		// Skip issue-only rules for judge checking
		if r.Judge == nil {
			continue
		}
		matches := false
		for _, w := range r.Windows {
			if !dayMatch(w.Weekdays, thisWD) {
				continue
			}
			if thisMin >= w.Start && thisMin < w.End {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		if best == nil || r.Priority < bestPrio || (r.Priority == bestPrio && ir.index > bestIndex) {
			best = &r
			bestPrio = r.Priority
			bestIndex = ir.index
		}
	}

	if best == nil || best.Judge == nil {
		return false, nil
	}
	return best.Judge.SUDOAllowed, nil
}

// ---- schedule: request management ---------------------------------------

// ScheduleRequest is a client-submitted rule approval request.
type ScheduleRequest struct {
	ClientName string `json:"client_name"`
	GrantedTo  string `json:"granted_to"`
	Status     string `json:"status"` // pending | approved | rejected
	Rule       Rule   `json:"rule"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

func SchedulePath(dataDir, target, group string) string {
	return filepath.Join(dataDir, "targets", target, "groups", group, "schedule-requests.json")
}

func SubmitRequest(dataDir, target, group, clientCN, grantedTo string, rule Rule) error {
	mu.Lock()
	defer mu.Unlock()

	path := SchedulePath(dataDir, target, group)
	var reqs []ScheduleRequest
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &reqs)
	}

	// Check for duplicate pending with same rule name
	for _, r := range reqs {
		if r.ClientName == clientCN && r.Rule.ID == rule.ID && r.Status == "pending" {
			return fmt.Errorf("已有待审批的同名规则 %q", rule.ID)
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	reqs = append(reqs, ScheduleRequest{
		ClientName: clientCN,
		GrantedTo:  grantedTo,
		Status:     "pending",
		Rule:       rule,
		CreatedAt:  now,
		UpdatedAt:  now,
	})

	os.MkdirAll(filepath.Dir(path), 0700)
	data, _ := json.MarshalIndent(reqs, "", "  ")
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func GetAllRequests(dataDir, target, group, clientCN string) ([]ScheduleRequest, error) {
	mu.Lock()
	defer mu.Unlock()

	path := SchedulePath(dataDir, target, group)
	var reqs []ScheduleRequest
	if data, err := os.ReadFile(path); err != nil {
		if os.IsNotExist(err) { return nil, nil }
		return nil, err
	} else {
		json.Unmarshal(data, &reqs)
	}
	if clientCN == "" { return reqs, nil }
	var filtered []ScheduleRequest
	for _, r := range reqs {
		if r.ClientName == clientCN { filtered = append(filtered, r) }
	}
	return filtered, nil
}

func ApproveRequest(dataDir, target, group, clientCN, ruleID string) error {
	mu.Lock()
	defer mu.Unlock()

	path := SchedulePath(dataDir, target, group)
	var reqs []ScheduleRequest
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &reqs)
	}
	for i, r := range reqs {
		if r.ClientName == clientCN && r.Rule.ID == ruleID && r.Status == "pending" {
			reqs[i].Status = "approved"
			reqs[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			data, _ := json.MarshalIndent(reqs, "", "  ")
			return os.WriteFile(path, append(data, '\n'), 0644)
		}
	}
	return fmt.Errorf("no pending request for client %q, rule %q", clientCN, ruleID)
}

func RevokeApproved(dataDir, target, group, clientCN string) error {
	mu.Lock()
	defer mu.Unlock()

	path := filepath.Join(dataDir, "targets", target, "groups", group, "schedules-approved.json")
	var approved []struct {
		ClientName string `json:"client_name"`
		Rules      []Rule `json:"rules"`
	}
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &approved)
	}
	for i := range approved {
		if approved[i].ClientName == clientCN {
			approved = append(approved[:i], approved[i+1:]...)
			os.MkdirAll(filepath.Dir(path), 0700)
			data, _ := json.MarshalIndent(approved, "", "  ")
			return os.WriteFile(path, append(data, '\n'), 0644)
		}
	}
	return fmt.Errorf("no approved rules for client %q", clientCN)
}

func GetApprovedRules(dataDir, target, group, clientCN string) ([]Rule, error) {
	mu.Lock()
	defer mu.Unlock()

	path := filepath.Join(dataDir, "targets", target, "groups", group, "schedules-approved.json")
	var approved []struct {
		ClientName string `json:"client_name"`
		Rules      []Rule `json:"rules"`
	}
	if data, err := os.ReadFile(path); err != nil {
		if os.IsNotExist(err) { return nil, nil }
		return nil, err
	} else {
		json.Unmarshal(data, &approved)
	}
	for _, a := range approved {
		if a.ClientName == clientCN { return a.Rules, nil }
	}
	return nil, nil
}

func dayMatch(days []int, wd int) bool {
	if len(days) == 0 {
		return true
	}
	for _, d := range days {
		if d == wd {
			return true
		}
	}
	return false
}

// ValidateRules validates all rules in a RulesFile.
func ValidateRules(rf *RulesFile) error {
	for _, r := range rf.Rules {
		if err := ValidateRule(r); err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
	}
	return nil
}

// GroupVersions holds the current version map for a target.
type GroupVersions struct {
	Issuers map[string]map[string]int `json:"issuers"` // issuer → group → version
}

// LoadGroupVersions reads group-versions.json for a target.
func LoadGroupVersions(dataDir, target string) (*GroupVersions, error) {
	path := filepath.Join(dataDir, "targets", target, "group-versions.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var gv GroupVersions
	if err := json.Unmarshal(data, &gv); err != nil {
		return nil, err
	}
	return &gv, nil
}

// SaveGroupVersions persists group versions.
func SaveGroupVersions(dataDir, target string, gv *GroupVersions) error {
	dir := filepath.Join(dataDir, "targets", target)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(gv, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "group-versions.json"), append(data, '\n'), 0644)
}

// IncrementGroupVersion bumps the version for a target+group and returns the new version.
func IncrementGroupVersion(dataDir, target, issuer, group string) (int, error) {
	mu.Lock()
	defer mu.Unlock()

	gv, err := LoadGroupVersions(dataDir, target)
	if err != nil {
		return 0, err
	}
	if gv == nil {
		gv = &GroupVersions{Issuers: make(map[string]map[string]int)}
	}
	if gv.Issuers[issuer] == nil {
		gv.Issuers[issuer] = make(map[string]int)
	}
	gv.Issuers[issuer][group]++
	ver := gv.Issuers[issuer][group]
	return ver, SaveGroupVersions(dataDir, target, gv)
}
