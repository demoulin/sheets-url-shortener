package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestCloudSeverity(t *testing.T) {
	tests := []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelDebug, "DEBUG"},
		{slog.LevelInfo, "INFO"},
		{slog.LevelWarn, "WARNING"}, // not "WARN" — Cloud Logging's enum
		{slog.LevelError, "ERROR"},
	}
	for _, tt := range tests {
		if got := cloudSeverity(tt.level); got != tt.want {
			t.Errorf("cloudSeverity(%v)=%q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestCloudLoggerFieldNames(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: cloudReplaceAttr}))

	logger.Warn("something happened")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("log line is not valid JSON: %v", err)
	}

	if entry["severity"] != "WARNING" {
		t.Errorf("severity=%v, want WARNING", entry["severity"])
	}
	if entry["message"] != "something happened" {
		t.Errorf("message=%v, want %q", entry["message"], "something happened")
	}
	if _, ok := entry["timestamp"]; !ok {
		t.Error("missing 'timestamp' field")
	}
	// default slog keys must not leak through
	for _, k := range []string{"level", "msg", "time"} {
		if _, ok := entry[k]; ok {
			t.Errorf("unexpected default slog key %q in output", k)
		}
	}
}
