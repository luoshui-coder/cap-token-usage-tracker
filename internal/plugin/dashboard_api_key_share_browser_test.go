package plugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAPIKeyShareInBrowser(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		browserTestUnavailable(t, "Node.js", err)
	}
	chrome, err := resolveBrowserTestChrome()
	if err != nil {
		browserTestUnavailable(t, "Chrome", err)
	}
	if _, err := os.Stat(filepath.Join("..", "..", "node_modules", "playwright-core", "package.json")); err != nil {
		browserTestUnavailable(t, "playwright-core", err)
	}
	path := filepath.Join(t.TempDir(), "dashboard.html")
	if err := os.WriteFile(path, []byte(fullDashboardHTML), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(node, filepath.Join("..", "..", "test", "dashboard_api_key_share.mjs"), path, chrome)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("API-key share browser check: %v\n%s", err, output)
	}
}
