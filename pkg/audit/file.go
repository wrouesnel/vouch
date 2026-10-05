package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// writerSink writes one JSON object per line to an io.Writer. If the writer is a file (or any
// Syncer) each record is flushed to stable storage before Log returns.
type writerSink struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
}

type syncer interface{ Sync() error }

// Log implements Sink.
func (s *writerSink) Log(_ context.Context, e Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: encoding event: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(line); err != nil {
		return fmt.Errorf("audit: writing event: %w", err)
	}
	if sync, ok := s.w.(syncer); ok {
		if err := sync.Sync(); err != nil {
			return fmt.Errorf("audit: flushing event: %w", err)
		}
	}
	return nil
}

// Close implements Sink.
func (s *writerSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}

// NewWriterSink returns a Sink that writes JSON lines to w. It doesn't take ownership of w.
func NewWriterSink(w io.Writer) Sink {
	return &writerSink{w: w}
}

// FileConfig configures a file audit sink.
type FileConfig struct {
	// Path is the file events are appended to, as JSON lines. It must be writable and on
	// durable storage; each event is fsync'd before the unlock proceeds.
	Path string `yaml:"path"`
}

// newFileSink opens the audit file for appending.
func newFileSink(cfg FileConfig) (Sink, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("audit: file sink needs a path")
	}
	file, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: opening %s: %w", cfg.Path, err)
	}
	return &writerSink{w: file, closer: file}, nil
}
