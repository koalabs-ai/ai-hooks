package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecStillRefusesPrintingASecretVariable(t *testing.T) {
	_, e, code := run(t, "", []string{"DB_PASSWORD=hunter2"}, "exec", "--", "sh -c 'echo $DB_PASSWORD'")
	if code != 2 || !strings.Contains(e, "ai-hooks [") {
		t.Errorf("code=%d stderr=%q", code, e)
	}
	// and a weak secret in an env-shaped file is redacted by shape (the NAME says password)
	d := t.TempDir()
	f := filepath.Join(d, "vars.txt")
	os.WriteFile(f, []byte("APP_DB_PASSWORD=hunter2x\nUSER=john\n"), 0o600)
	out, _, code := run(t, "", nil, "exec", "--", "cat", f)
	if code != 0 || strings.Contains(out, "hunter2x") || !strings.Contains(out, "USER=john") {
		t.Errorf("out=%q code=%d", out, code)
	}
}
