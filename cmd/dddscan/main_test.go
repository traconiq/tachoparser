package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The exit code is the part of this tool other things depend on: it is what a
// cron sweeping the quarantine directory branches on. So it is tested through
// the real binary rather than by calling functions, which is the only way to
// cover flag parsing and the exit path together.

func build(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "dddscan")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func run(t *testing.T, bin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return string(out), code
}

const corpus = "../../test/data"

func aGoodVuFile(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(corpus)
	if err != nil {
		t.Skipf("no corpus: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToUpper(e.Name()), ".DDD") && !strings.HasPrefix(e.Name(), "C_") {
			return filepath.Join(corpus, e.Name())
		}
	}
	t.Skip("no vu file in the corpus")
	return ""
}

func TestExitZeroOnGoodFile(t *testing.T) {
	bin := build(t)
	out, code := run(t, bin, aGoodVuFile(t))
	if code != exitOK {
		t.Errorf("exit = %d, want %d\n%s", code, exitOK, out)
	}
	if !strings.Contains(out, "ok —") {
		t.Errorf("output does not report ok:\n%s", out)
	}
}

func TestExitNonZeroOnTruncatedFile(t *testing.T) {
	bin := build(t)
	good, err := os.ReadFile(aGoodVuFile(t))
	if err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(t.TempDir(), "broken.DDD")
	if err := os.WriteFile(broken, good[:len(good)/2], 0644); err != nil {
		t.Fatal(err)
	}

	out, code := run(t, bin, broken)
	if code != exitProblem {
		t.Errorf("exit = %d, want %d\n%s", code, exitProblem, out)
	}
	if !strings.Contains(out, "FAILED") {
		t.Errorf("output does not report a failure:\n%s", out)
	}
}

func TestExitNonZeroOnNonDDD(t *testing.T) {
	bin := build(t)
	p := filepath.Join(t.TempDir(), "not.DDD")
	if err := os.WriteFile(p, []byte("this is not a download"), 0644); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, bin, p)
	if code != exitProblem {
		t.Errorf("exit = %d, want %d\n%s", code, exitProblem, out)
	}
}

// A directory argument without -r must be an error rather than a silent sweep:
// a mistyped path should not quietly walk a tree.
func TestDirectoryNeedsRecurse(t *testing.T) {
	bin := build(t)
	out, code := run(t, bin, corpus)
	if code != exitUsage {
		t.Errorf("exit = %d, want %d (usage)\n%s", code, exitUsage, out)
	}
	if !strings.Contains(out, "-r") {
		t.Errorf("error does not mention -r:\n%s", out)
	}
}

func TestRecurseScansCorpusCleanly(t *testing.T) {
	bin := build(t)
	out, code := run(t, bin, "-r", corpus)
	if code != exitOK {
		t.Errorf("the corpus should scan cleanly, exit = %d\n%s", code, out)
	}
	if !strings.Contains(out, "scanned") {
		t.Errorf("no summary line:\n%s", out)
	}
}

func TestQuietHidesGoodFiles(t *testing.T) {
	bin := build(t)
	out, code := run(t, bin, "-q", "-r", corpus)
	if code != exitOK {
		t.Fatalf("exit = %d\n%s", code, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, ": ok —") {
			t.Errorf("-q printed a clean file: %s", line)
		}
	}
}

func TestRequireReportsAbsentTag(t *testing.T) {
	bin := build(t)
	// 76ff is not a real transfer response, so no file can contain it.
	out, code := run(t, bin, "-require", "76ff", aGoodVuFile(t))
	if code != exitProblem {
		t.Errorf("exit = %d, want %d\n%s", code, exitProblem, out)
	}
	if !strings.Contains(out, "INCOMPLETE") || !strings.Contains(out, "76ff") {
		t.Errorf("output does not name the absent tag:\n%s", out)
	}
}

func TestJSONIsValidAndMarksFailure(t *testing.T) {
	bin := build(t)
	p := filepath.Join(t.TempDir(), "not.DDD")
	if err := os.WriteFile(p, []byte("nope"), 0644); err != nil {
		t.Fatal(err)
	}
	out, _ := run(t, bin, "-json", p)
	for _, want := range []string{`"ok": false`, `"problems"`, `"code": "unknown_tag"`} {
		if !strings.Contains(out, want) {
			t.Errorf("json output missing %s:\n%s", want, out)
		}
	}
}

func TestVuAndCardAreMutuallyExclusive(t *testing.T) {
	bin := build(t)
	out, code := run(t, bin, "-vu", "-card", aGoodVuFile(t))
	if code != exitUsage {
		t.Errorf("exit = %d, want %d\n%s", code, exitUsage, out)
	}
}
