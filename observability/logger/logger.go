// Package logger provides structured, leveled logging for single-auth.
package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Level is ordered from the most verbose to the most severe level.
type Level string

const (
	Debug   Level = "debug"
	Info    Level = "info"
	Success Level = "success"
	Warn    Level = "warn"
	Error   Level = "error"
)

var levels = [...]Level{Debug, Info, Success, Warn, Error}

// Handler receives the unformatted message when a custom logger is supplied.
// Success is reported as Info because the public callback does not expose a
// separate success level.
type Handler func(level Level, message string, args ...any)

// Options configures a Logger. Level defaults to Warn. DisableColors is a
// pointer so an omitted value can retain terminal auto-detection.
type Options struct {
	Disabled      bool
	DisableColors *bool
	Level         Level
	Log           Handler

	// Output fields are useful for hosts and deterministic tests. Nil selects
	// stdout for debug/info/success and stderr for warn/error.
	Output      io.Writer
	ErrorOutput io.Writer
	Now         func() time.Time
}

// Logger is immutable and safe for concurrent use when its configured writer
// or custom callback is safe for concurrent use.
type Logger struct {
	enabled       bool
	colorsEnabled bool
	level         Level
	log           Handler
	output        io.Writer
	errorOutput   io.Writer
	now           func() time.Time
}

// New snapshots options and creates a logger.
func New(options Options) (*Logger, error) {
	level := options.Level
	if level == "" {
		level = Warn
	}
	if !ValidLevel(level) || level == Success {
		return nil, fmt.Errorf("single-auth/logger: invalid configured level %q", level)
	}
	output := options.Output
	if output == nil {
		output = os.Stdout
	}
	errorOutput := options.ErrorOutput
	if errorOutput == nil {
		errorOutput = os.Stderr
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	colors := terminalColorsEnabled(output)
	if options.DisableColors != nil {
		colors = !*options.DisableColors
	}
	return &Logger{
		enabled: !options.Disabled, colorsEnabled: colors, level: level,
		log: options.Log, output: output, errorOutput: errorOutput, now: now,
	}, nil
}

// MustNew creates a Logger or panics for invalid static configuration.
func MustNew(options Options) *Logger {
	result, err := New(options)
	if err != nil {
		panic(err)
	}
	return result
}

// ValidLevel reports whether level is supported.
func ValidLevel(level Level) bool {
	for _, candidate := range levels {
		if level == candidate {
			return true
		}
	}
	return false
}

// ShouldPublish applies the configured threshold order.
func ShouldPublish(current, candidate Level) bool {
	return levelIndex(candidate) >= levelIndex(current)
}

func levelIndex(level Level) int {
	for index, candidate := range levels {
		if level == candidate {
			return index
		}
	}
	return -1
}

// Level returns the configured threshold.
func (logger *Logger) Level() Level {
	if logger == nil {
		return Warn
	}
	return logger.level
}

func (logger *Logger) Debug(message string, args ...any)   { logger.publish(Debug, message, args...) }
func (logger *Logger) Info(message string, args ...any)    { logger.publish(Info, message, args...) }
func (logger *Logger) Success(message string, args ...any) { logger.publish(Success, message, args...) }
func (logger *Logger) Warn(message string, args ...any)    { logger.publish(Warn, message, args...) }
func (logger *Logger) Error(message string, args ...any)   { logger.publish(Error, message, args...) }

func (logger *Logger) publish(level Level, message string, args ...any) {
	if logger == nil || !logger.enabled || !ShouldPublish(logger.level, level) {
		return
	}
	if logger.log != nil {
		callbackLevel := level
		if callbackLevel == Success {
			callbackLevel = Info
		}
		logger.log(callbackLevel, message, args...)
		return
	}
	formatted := formatMessage(logger.now().UTC(), level, message, logger.colorsEnabled)
	writer := logger.output
	if level == Warn || level == Error {
		writer = logger.errorOutput
	}
	values := make([]any, 0, 1+len(args))
	values = append(values, formatted)
	values = append(values, args...)
	_, _ = fmt.Fprintln(writer, values...)
}

func formatMessage(now time.Time, level Level, message string, colors bool) string {
	timestamp := now.Format("2006-01-02T15:04:05.000Z")
	upper := strings.ToUpper(string(level))
	if !colors {
		return timestamp + " " + upper + " [single-auth]: " + message
	}
	return "\x1b[2m" + timestamp + "\x1b[0m " + levelColor(level) + upper +
		"\x1b[0m \x1b[1m[single-auth]:\x1b[0m " + message
}

func levelColor(level Level) string {
	switch level {
	case Info:
		return "\x1b[34m"
	case Success:
		return "\x1b[32m"
	case Warn:
		return "\x1b[33m"
	case Error:
		return "\x1b[31m"
	default:
		return "\x1b[35m"
	}
}

func terminalColorsEnabled(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return strings.ToLower(os.Getenv("TERM")) != "dumb"
}
