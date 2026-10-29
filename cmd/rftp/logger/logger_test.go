// SPDX-License-Identifier: MIT

package logger

import (
	"bytes"
	"strings"
	"testing"
)

// swapWriters replaces the output writers with buffers and returns them
// plus a restore function.
func swapWriters(t *testing.T) (out, errOut *bytes.Buffer, restore func()) {
	t.Helper()
	out, errOut = &bytes.Buffer{}, &bytes.Buffer{}
	oldOut, oldErr := stdout, stderr
	stdout, stderr = out, errOut
	return out, errOut, func() { stdout, stderr = oldOut, oldErr }
}

func TestInfoGoesToStdout(t *testing.T) {
	out, errOut, restore := swapWriters(t)
	defer restore()
	SetLevel("info")

	Info("hello %s", "world")
	if !strings.Contains(out.String(), "INFO hello world") {
		t.Errorf("stdout = %q, want INFO hello world", out.String())
	}
	if errOut.Len() != 0 {
		t.Errorf("stderr = %q, want empty", errOut.String())
	}
}

func TestWarnAndErrorGoToStderr(t *testing.T) {
	out, errOut, restore := swapWriters(t)
	defer restore()
	SetLevel("info")

	Warn("careful")
	Error("broken %d", 42)
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty", out.String())
	}
	if !strings.Contains(errOut.String(), "WARN careful") {
		t.Errorf("stderr = %q, want WARN careful", errOut.String())
	}
	if !strings.Contains(errOut.String(), "ERROR broken 42") {
		t.Errorf("stderr = %q, want ERROR broken 42", errOut.String())
	}
}

func TestLevelFiltering(t *testing.T) {
	out, errOut, restore := swapWriters(t)
	defer restore()
	SetLevel("warn")

	Debug("hidden")
	Info("hidden too")
	Warn("shown")
	Error("shown")

	if strings.Contains(out.String(), "hidden") || strings.Contains(errOut.String(), "hidden") {
		t.Errorf("debug/info messages should be filtered at warn level: out=%q err=%q",
			out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "shown") {
		t.Errorf("warn/error messages should be logged at warn level: err=%q", errOut.String())
	}
}

func TestSetLevelUnknownIgnored(t *testing.T) {
	SetLevel("info")
	SetLevel("not-a-level")
	if GetLevel() != LevelInfo {
		t.Errorf("GetLevel() = %v, want LevelInfo after unknown level", GetLevel())
	}
	SetLevel("debug")
	if GetLevel() != LevelDebug {
		t.Errorf("GetLevel() = %v, want LevelDebug", GetLevel())
	}
}

func TestLogLineHasTimestampAndLevel(t *testing.T) {
	out, _, restore := swapWriters(t)
	defer restore()
	SetLevel("info")

	Info("msg")
	line := out.String()
	// Format: "<RFC3339 UTC timestamp> INFO msg"
	if !strings.HasSuffix(line, " INFO msg\n") {
		t.Errorf("line = %q, want suffix ' INFO msg'", line)
	}
	if len(strings.Fields(strings.TrimSpace(line))) < 3 {
		t.Errorf("line = %q, want timestamp, level and message", line)
	}
}
