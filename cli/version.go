package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var cliVersion = "dev"

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
		checkForUpdate()
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

func checkForUpdate() {
	cachePath := getVersionCachePath()

	// Check cache first
	if data, err := os.ReadFile(cachePath); err == nil {
		var cached versionCheck
		if json.Unmarshal(data, &cached) == nil {
			if t, err := time.Parse(time.RFC3339, cached.CheckedAt); err == nil {
				if time.Since(t) < 24*time.Hour {
					printUpgradeHint(cached.Version)
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

	printUpgradeHint(remote.Version)
}

func printUpgradeHint(latest string) {
	if latest == "" || latest == cliVersion || cliVersion == "dev" {
		return
	}
	fmt.Printf("\nqntm %s is available (you have %s). Run: uvx qntm --upgrade\n", latest, cliVersion)
}
