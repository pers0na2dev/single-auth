package logger

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestShouldPublishThresholdOrder(t *testing.T) {
	for _, test := range []struct {
		current, candidate Level
		want               bool
	}{
		{Debug, Debug, true}, {Debug, Error, true},
		{Info, Debug, false}, {Info, Info, true},
		{Warn, Success, false}, {Warn, Warn, true}, {Warn, Error, true},
		{Error, Warn, false}, {Error, Error, true},
	} {
		if got := ShouldPublish(test.current, test.candidate); got != test.want {
			t.Fatalf("ShouldPublish(%q, %q) = %t, want %t", test.current, test.candidate, got, test.want)
		}
	}
}

func TestCustomLoggerReceivesRawMessageAndMapsSuccessToInfo(t *testing.T) {
	type entry struct {
		level   Level
		message string
		args    []any
	}
	var entries []entry
	logger := MustNew(Options{
		Level: Debug,
		Log: func(level Level, message string, args ...any) {
			entries = append(entries, entry{level: level, message: message, args: args})
		},
	})
	logger.Debug("debug", 1)
	logger.Success("done", map[string]any{"ok": true})
	if len(entries) != 2 || entries[0].level != Debug || entries[1].level != Info {
		t.Fatalf("entries = %#v", entries)
	}
	if entries[1].message != "done" || !reflect.DeepEqual(entries[1].args, []any{map[string]any{"ok": true}}) {
		t.Fatalf("success entry = %#v", entries[1])
	}
}

func TestDefaultFormattingThresholdAndStreams(t *testing.T) {
	var output, errors bytes.Buffer
	disableColors := true
	logger := MustNew(Options{
		Level: Warn, DisableColors: &disableColors, Output: &output, ErrorOutput: &errors,
		Now: func() time.Time { return time.Date(2026, 8, 8, 12, 34, 56, 789000000, time.UTC) },
	})
	logger.Info("hidden")
	logger.Warn("careful", "detail")
	logger.Error("failed")
	if output.Len() != 0 {
		t.Fatalf("stdout = %q", output.String())
	}
	want := "2026-08-08T12:34:56.789Z WARN [single-auth]: careful detail\n" +
		"2026-08-08T12:34:56.789Z ERROR [single-auth]: failed\n"
	if errors.String() != want {
		t.Fatalf("stderr = %q, want %q", errors.String(), want)
	}

	disabled := MustNew(Options{Disabled: true, Output: &output, ErrorOutput: &errors})
	disabled.Error("ignored")
	if errors.String() != want {
		t.Fatalf("disabled logger wrote output: %q", errors.String())
	}
}

func TestInvalidConfiguredLevel(t *testing.T) {
	if _, err := New(Options{Level: Success}); err == nil {
		t.Fatal("success should not be accepted as a public threshold")
	}
	if _, err := New(Options{Level: "trace"}); err == nil {
		t.Fatal("unknown level should fail")
	}
}
