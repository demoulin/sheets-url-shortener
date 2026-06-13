package main

import (
	"log/slog"
	"os"
)

// reportedErrorType is the Cloud Error Reporting type marker. An entry carrying
// this @type (with ERROR severity and a stack trace) is grouped as an error in
// Error Reporting.
const reportedErrorType = "type.googleapis.com/google.devtools.clouderrorreporting.v1beta1.ReportedErrorEvent"

// newCloudLogger builds a JSON slog.Logger whose field names and level strings
// match Google Cloud Logging's structured-log conventions: `level` → `severity`
// (with WARN mapped to WARNING), `msg` → `message`, and `time` → `timestamp`.
func newCloudLogger() *slog.Logger {
	opts := &slog.HandlerOptions{ReplaceAttr: cloudReplaceAttr}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

// cloudReplaceAttr renames slog's default keys to Cloud Logging's special
// fields and rewrites the level value to a Cloud severity string.
func cloudReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.LevelKey:
		a.Key = "severity"
		if l, ok := a.Value.Any().(slog.Level); ok {
			a.Value = slog.StringValue(cloudSeverity(l))
		}
	case slog.MessageKey:
		a.Key = "message"
	case slog.TimeKey:
		a.Key = "timestamp"
	}
	return a
}

// cloudSeverity maps an slog.Level to a Cloud Logging severity string.
func cloudSeverity(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARNING"
	case l >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}
