package cli

import "testing"

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		name    string
		latest  string
		current string
		want    bool
	}{
		{name: "upgrade same prefix", latest: "v0.1.2", current: "v0.1.1", want: true},
		{name: "upgrade mixed prefix", latest: "0.2.0", current: "v0.1.9", want: true},
		{name: "equal", latest: "v0.1.1", current: "v0.1.1", want: false},
		{name: "downgrade", latest: "v0.1.1", current: "v0.1.6", want: false},
		{name: "stable newer than prerelease", latest: "v1.0.0", current: "v1.0.0-beta.1", want: true},
		{name: "prerelease older than stable", latest: "v1.0.0-beta.1", current: "v1.0.0", want: false},
		{name: "dev current disabled", latest: "v1.0.0", current: "dev", want: false},
		{name: "invalid latest", latest: "latest", current: "v0.1.0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNewerVersion(tt.latest, tt.current)
			if got != tt.want {
				t.Fatalf("isNewerVersion(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
			}
		})
	}
}

func TestSetUpgradeHintSkipsDowngrade(t *testing.T) {
	orig := cliVersion
	defer func() {
		cliVersion = orig
		setUpdateMessage("")
	}()

	cliVersion = "v0.1.6"
	setUpdateMessage("")

	setUpgradeHint("v0.1.1", false)

	if got := getUpdateMessage(); got != "" {
		t.Fatalf("expected no update message for downgrade, got %q", got)
	}
}

func TestSetUpgradeHintShowsUpgrade(t *testing.T) {
	orig := cliVersion
	defer func() {
		cliVersion = orig
		setUpdateMessage("")
	}()

	cliVersion = "v0.1.1"
	setUpdateMessage("")

	setUpgradeHint("v0.1.6", false)

	if got := getUpdateMessage(); got == "" {
		t.Fatalf("expected update message for valid upgrade")
	}
}
