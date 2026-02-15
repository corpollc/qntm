package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

var cliVersion = "dev"

// updateMessage is set by the background version check goroutine.
var updateMessage string
var updateOnce sync.Once
var updateDone = make(chan struct{})

// SetVersion sets the CLI version (called from main with build-time value).
func SetVersion(v string) {
	cliVersion = v
	rootCmd.Version = v
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version and check for updates",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("qntm %s\n", cliVersion)
		// For the version command, run synchronously so the user sees the result.
		checkForUpdate(true)
	},
}

type versionCheck struct {
	Version   string `json:"version"`
	CheckedAt string `json:"checked_at"`
}

type remoteVersion struct {
	Version string `json:"version"`
}

func getVersionCachePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".qntm", "version-check.json")
}

// startBackgroundUpdateCheck kicks off a non-blocking version check.
// Call this from PersistentPostRun. The result is printed after the command.
func startBackgroundUpdateCheck() {
	updateOnce.Do(func() {
		go func() {
			defer close(updateDone)
			checkForUpdate(false)
		}()
	})
}

// waitAndPrintUpdateHint waits for the background check and prints if needed.
func waitAndPrintUpdateHint() {
	<-updateDone
	if updateMessage != "" {
		fmt.Fprintln(os.Stderr, updateMessage)
	}
}

func checkForUpdate(synchronous bool) {
	cachePath := getVersionCachePath()

	// Check cache first
	if data, err := os.ReadFile(cachePath); err == nil {
		var cached versionCheck
		if json.Unmarshal(data, &cached) == nil {
			// If cached says we're out of date, just print — no need to re-fetch.
			if cached.Version != "" && cached.Version != cliVersion && cliVersion != "dev" {
				setUpgradeHint(cached.Version, synchronous)
				return
			}
			// Versions matched last check — only re-fetch if cache is stale.
			if t, err := time.Parse(time.RFC3339, cached.CheckedAt); err == nil {
				if time.Since(t) < 24*time.Hour {
					return
				}
			}
		}
	}

	// Fetch remote version with 2s timeout
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://qntm.corpo.llc/version.json")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var remote remoteVersion
	if err := json.NewDecoder(resp.Body).Decode(&remote); err != nil {
		return
	}

	// Cache result
	cached := versionCheck{
		Version:   remote.Version,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if data, err := json.Marshal(cached); err == nil {
		os.MkdirAll(filepath.Dir(cachePath), 0o755)
		os.WriteFile(cachePath, data, 0o644)
	}

	setUpgradeHint(remote.Version, synchronous)
}

func setUpgradeHint(latest string, printNow bool) {
	if latest == "" || latest == cliVersion || cliVersion == "dev" {
		return
	}
	msg := fmt.Sprintf("\nUpdate available: qntm %s → %s. Run: uvx qntm@latest --version", cliVersion, latest)
	if printNow {
		fmt.Fprintln(os.Stderr, msg)
	} else {
		updateMessage = msg
	}
}
