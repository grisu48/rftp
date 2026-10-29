package ftp

import "testing"

func TestParseCommand(t *testing.T) {
	tests := []struct {
		line     string
		wantName string
		wantArg  string
	}{
		{"USER anonymous\r\n", "USER", "anonymous"},
		{"USER anonymous", "USER", "anonymous"},
		{"pass secret\r\n", "PASS", "secret"},
		{"pwd\r\n", "PWD", ""},
		{"PWD", "PWD", ""},
		{"CWD /pub\r\n", "CWD", "/pub"},
		{"RETR file.txt\r\n", "RETR", "file.txt"},
		{"TYPE A N\r\n", "TYPE", "A N"},
		{"OPTS UTF8 ON\r\n", "OPTS", "UTF8 ON"},
		{"  LIST  -la /pub \r\n", "LIST", "-la /pub "},
		{"\r\n", "", ""},
		{"   \r\n", "", ""},
		{"", "", ""},
		{"NOOP\r\n", "NOOP", ""},
	}
	for _, tt := range tests {
		got := ParseCommand(tt.line)
		if got.Name != tt.wantName || got.Arg != tt.wantArg {
			t.Errorf("ParseCommand(%q) = {%q, %q}, want {%q, %q}",
				tt.line, got.Name, got.Arg, tt.wantName, tt.wantArg)
		}
	}
}

func TestParseCommandNameIsUpperCase(t *testing.T) {
	cmd := ParseCommand("retr SomeFile.TXT\r\n")
	if cmd.Name != "RETR" {
		t.Errorf("Name = %q, want RETR", cmd.Name)
	}
	// The argument keeps its case.
	if cmd.Arg != "SomeFile.TXT" {
		t.Errorf("Arg = %q, want SomeFile.TXT", cmd.Arg)
	}
}
