package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type cliResponse struct {
	OK    bool                         `json:"ok"`
	Kind  string                       `json:"kind"`
	Data  map[string]json.RawMessage   `json:"data"`
	Error string                       `json:"error"`
	Rules map[string]json.RawMessage   `json:"rules"`
}

type stepResult struct {
	Phase    string        `json:"phase"`
	Name     string        `json:"name"`
	Duration time.Duration `json:"duration"`
	OK       bool          `json:"ok"`
	Detail   string        `json:"detail,omitempty"`
}

type summary struct {
	WorkDir        string                 `json:"work_dir"`
	QntmBin        string                 `json:"qntm_bin"`
	Storage        string                 `json:"storage,omitempty"`
	DropboxURL     string                 `json:"dropbox_url,omitempty"`
	StartedAt      time.Time              `json:"started_at"`
	FinishedAt     time.Time              `json:"finished_at"`
	TotalDuration  time.Duration          `json:"total_duration"`
	Steps          []stepResult           `json:"steps"`
	PhaseDurations map[string]time.Duration `json:"phase_durations"`
}

type harness struct {
	qntmBin    string
	workDir    string
	storage    string
	dropboxURL string
	timeout    time.Duration
	verbose    bool
	steps      []stepResult
}

func main() {
	var qntmBin string
	var workDir string
	var storage string
	var dropboxURL string
	var timeout time.Duration
	var keepWorkdir bool
	var jsonOutput bool
	var verbose bool

	flag.StringVar(&qntmBin, "qntm-bin", "./qntm", "Path to qntm binary")
	flag.StringVar(&workDir, "workdir", "", "Working directory for temp profiles (default: temp dir)")
	flag.StringVar(&storage, "storage", "", "Optional --storage value passed to qntm")
	flag.StringVar(&dropboxURL, "dropbox-url", "", "Optional --dropbox-url value passed to qntm")
	flag.DurationVar(&timeout, "timeout", 45*time.Second, "Per-command timeout")
	flag.BoolVar(&keepWorkdir, "keep-workdir", false, "Keep working directory after run")
	flag.BoolVar(&jsonOutput, "json", false, "Emit summary as JSON")
	flag.BoolVar(&verbose, "verbose", false, "Print command execution details")
	flag.Parse()

	if workDir == "" {
		dir, err := os.MkdirTemp("", "qntm-perf-*")
		if err != nil {
			fatalf("failed to create temp dir: %v", err)
		}
		workDir = dir
	}

	if !keepWorkdir {
		defer os.RemoveAll(workDir)
	}

	absBin, err := resolveBinary(qntmBin)
	if err != nil {
		fatalf("failed to resolve qntm binary %q: %v", qntmBin, err)
	}

	h := &harness{
		qntmBin:    absBin,
		workDir:    workDir,
		storage:    storage,
		dropboxURL: dropboxURL,
		timeout:    timeout,
		verbose:    verbose,
	}

	start := time.Now()
	if err := h.run(); err != nil {
		fatalf("perf run failed: %v", err)
	}
	finished := time.Now()

	phaseDurations := make(map[string]time.Duration)
	for _, step := range h.steps {
		phaseDurations[step.Phase] += step.Duration
	}

	result := summary{
		WorkDir:         workDir,
		QntmBin:         absBin,
		Storage:         storage,
		DropboxURL:      dropboxURL,
		StartedAt:       start,
		FinishedAt:      finished,
		TotalDuration:   finished.Sub(start),
		Steps:           h.steps,
		PhaseDurations:  phaseDurations,
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fatalf("failed to encode JSON summary: %v", err)
		}
		return
	}

	printSummary(result)
}

func printSummary(result summary) {
	fmt.Printf("qntm perf summary\n")
	fmt.Printf("  qntm binary: %s\n", result.QntmBin)
	fmt.Printf("  workdir: %s\n", result.WorkDir)
	if result.Storage != "" {
		fmt.Printf("  storage: %s\n", result.Storage)
	}
	if result.DropboxURL != "" {
		fmt.Printf("  dropbox_url: %s\n", result.DropboxURL)
	}
	fmt.Println()

	for _, step := range result.Steps {
		status := "ok"
		if !step.OK {
			status = "fail"
		}
		fmt.Printf("  %-7s %-8s %-28s %8.3fs", status, step.Phase, step.Name, step.Duration.Seconds())
		if step.Detail != "" {
			fmt.Printf("  (%s)", step.Detail)
		}
		fmt.Println()
	}

	fmt.Println()
	phaseNames := make([]string, 0, len(result.PhaseDurations))
	for name := range result.PhaseDurations {
		phaseNames = append(phaseNames, name)
	}
	sort.Strings(phaseNames)
	for _, name := range phaseNames {
		fmt.Printf("  phase %-8s %8.3fs\n", name, result.PhaseDurations[name].Seconds())
	}
	fmt.Printf("  total       %8.3fs\n", result.TotalDuration.Seconds())
}

func (h *harness) run() error {
	profiles := map[string]string{
		"alice": filepath.Join(h.workDir, "alice"),
		"bob":   filepath.Join(h.workDir, "bob"),
		"carol": filepath.Join(h.workDir, "carol"),
		"dave":  filepath.Join(h.workDir, "dave"),
	}

	for _, dir := range profiles {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create profile dir %s: %w", dir, err)
		}
	}

	for _, name := range []string{"alice", "bob", "carol", "dave"} {
		if _, err := h.runStep("setup", "identity.generate."+name, profiles[name], "identity", "generate"); err != nil {
			return err
		}
	}

	if err := h.runDirectScenario(profiles); err != nil {
		return err
	}
	if err := h.runGroupScenario(profiles); err != nil {
		return err
	}

	return nil
}

func (h *harness) runDirectScenario(profiles map[string]string) error {
	resp, err := h.runStep("direct", "convo.create", profiles["alice"], "convo", "create", "--name", "perf-direct")
	if err != nil {
		return err
	}
	token, err := responseString(resp, "invite_token")
	if err != nil {
		return err
	}
	convID, err := responseString(resp, "conversation_id")
	if err != nil {
		return err
	}

	if _, err := h.runStep("direct", "convo.join.bob", profiles["bob"], "convo", "join", token, "--name", "perf-direct"); err != nil {
		return err
	}
	if _, err := h.runStep("direct", "send.alice", profiles["alice"], "send", convID, "perf direct ping"); err != nil {
		return err
	}
	if _, err := h.runStep("direct", "recv.bob", profiles["bob"], "recv", convID); err != nil {
		return err
	}
	if _, err := h.runStep("direct", "send.bob", profiles["bob"], "send", convID, "perf direct pong"); err != nil {
		return err
	}
	if _, err := h.runStep("direct", "recv.alice", profiles["alice"], "recv", convID); err != nil {
		return err
	}

	return nil
}

func (h *harness) runGroupScenario(profiles map[string]string) error {
	resp, err := h.runStep("group", "convo.create.group", profiles["alice"], "convo", "create", "--group", "--name", "perf-group")
	if err != nil {
		return err
	}
	token, err := responseString(resp, "invite_token")
	if err != nil {
		return err
	}
	convID, err := responseString(resp, "conversation_id")
	if err != nil {
		return err
	}

	if _, err := h.runStep("group", "convo.join.bob", profiles["bob"], "convo", "join", token, "--name", "perf-group"); err != nil {
		return err
	}
	if _, err := h.runStep("group", "convo.join.carol", profiles["carol"], "convo", "join", token, "--name", "perf-group"); err != nil {
		return err
	}
	if _, err := h.runStep("group", "convo.join.dave", profiles["dave"], "convo", "join", token, "--name", "perf-group"); err != nil {
		return err
	}

	// sends + receives x3
	if _, err := h.runStep("group", "send.alice.1", profiles["alice"], "send", convID, "group message from alice"); err != nil {
		return err
	}
	if _, err := h.runStep("group", "send.bob.1", profiles["bob"], "send", convID, "group message from bob"); err != nil {
		return err
	}
	if _, err := h.runStep("group", "recv.bob.1", profiles["bob"], "recv", convID); err != nil {
		return err
	}
	if _, err := h.runStep("group", "recv.carol.1", profiles["carol"], "recv", convID); err != nil {
		return err
	}
	if _, err := h.runStep("group", "recv.dave.1", profiles["dave"], "recv", convID); err != nil {
		return err
	}

	// sends + receives x4
	if _, err := h.runStep("group", "send.carol.2", profiles["carol"], "send", convID, "group message from carol"); err != nil {
		return err
	}
	if _, err := h.runStep("group", "send.dave.2", profiles["dave"], "send", convID, "group message from dave"); err != nil {
		return err
	}
	if _, err := h.runStep("group", "recv.alice.2", profiles["alice"], "recv", convID); err != nil {
		return err
	}
	if _, err := h.runStep("group", "recv.bob.2", profiles["bob"], "recv", convID); err != nil {
		return err
	}
	if _, err := h.runStep("group", "recv.carol.2", profiles["carol"], "recv", convID); err != nil {
		return err
	}
	if _, err := h.runStep("group", "recv.dave.2", profiles["dave"], "recv", convID); err != nil {
		return err
	}

	return nil
}

func (h *harness) runStep(phase, name, profileDir string, args ...string) (*cliResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	cmdArgs := make([]string, 0, len(args)+6)
	cmdArgs = append(cmdArgs, "--config-dir", profileDir)
	if h.storage != "" {
		cmdArgs = append(cmdArgs, "--storage", h.storage)
	}
	if h.dropboxURL != "" {
		cmdArgs = append(cmdArgs, "--dropbox-url", h.dropboxURL)
	}
	cmdArgs = append(cmdArgs, args...)

	start := time.Now()
	cmd := exec.CommandContext(ctx, h.qntmBin, cmdArgs...)
	out, err := cmd.CombinedOutput()
	duration := time.Since(start)

	if h.verbose {
		fmt.Printf("[%s/%s] %s %s (%.3fs)\n", phase, name, h.qntmBin, strings.Join(cmdArgs, " "), duration.Seconds())
	}

	resp, parseErr := decodeCLIResponse(out)
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = err.Error()
		}
		h.steps = append(h.steps, stepResult{
			Phase:    phase,
			Name:     name,
			Duration: duration,
			OK:       false,
			Detail:   truncate(detail, 240),
		})
		return nil, fmt.Errorf("%s failed: %w: %s", name, err, detail)
	}
	if parseErr != nil {
		h.steps = append(h.steps, stepResult{
			Phase:    phase,
			Name:     name,
			Duration: duration,
			OK:       false,
			Detail:   "invalid json response",
		})
		return nil, fmt.Errorf("%s returned non-json output: %w", name, parseErr)
	}
	if !resp.OK {
		detail := resp.Error
		if detail == "" {
			detail = string(out)
		}
		h.steps = append(h.steps, stepResult{
			Phase:    phase,
			Name:     name,
			Duration: duration,
			OK:       false,
			Detail:   truncate(detail, 240),
		})
		return nil, fmt.Errorf("%s returned error: %s", name, detail)
	}

	h.steps = append(h.steps, stepResult{
		Phase:    phase,
		Name:     name,
		Duration: duration,
		OK:       true,
	})
	return resp, nil
}

func decodeCLIResponse(output []byte) (*cliResponse, error) {
	var resp cliResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func responseString(resp *cliResponse, key string) (string, error) {
	if resp == nil || resp.Data == nil {
		return "", errors.New("missing response data")
	}
	raw, ok := resp.Data[key]
	if !ok {
		return "", fmt.Errorf("missing response data key %q", key)
	}

	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("invalid %q value: %w", key, err)
	}
	if value == "" {
		return "", fmt.Errorf("empty %q value", key)
	}
	return value, nil
}

func resolveBinary(pathOrName string) (string, error) {
	if strings.Contains(pathOrName, "/") {
		abs, err := filepath.Abs(pathOrName)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(abs); err != nil {
			return "", err
		}
		return abs, nil
	}
	return exec.LookPath(pathOrName)
}

func truncate(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	if max < 4 {
		return value[:max]
	}
	return value[:max-3] + "..."
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "qntm-perf: "+format+"\n", args...)
	os.Exit(1)
}
