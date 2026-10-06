package observability

import (
	"fmt"
	"io"
	"log/slog"
)

// NewLogger returns a JSON logger that writes to w and tags every record with
// the service name. The parameter 'level' is "debug", "info", "warn" or "error".
// Anything else is an error rather than a silent fallback.
func NewLogger(w io.Writer, service, level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("observability: log level %q: %w", level, err)
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l})
	return slog.New(h).With("service", service), nil
}
