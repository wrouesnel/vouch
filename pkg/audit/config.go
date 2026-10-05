package audit

import (
	"io"
)

// Config selects the audit sinks. Any combination may be set; events go to all of them and the
// unlock is gated on all of them committing. If none is set, events go to the default writer
// (process stderr) so there's always a trail, though a durable sink should be configured.
//
// DSN and token files are resolved by the caller before New is called.
type Config struct {
	// File appends JSON lines to a local file.
	File *FileConfig `yaml:"file"`
	// SQL inserts a row per event.
	SQL *SQLConfig `yaml:"sql"`
	// HTTP POSTs events to an endpoint such as Splunk HEC.
	HTTP *HTTPConfig `yaml:"http"`
	// Stderr writes JSON lines to the process's standard error. It defaults to on only when no
	// other sink is configured; set it explicitly to add or suppress it.
	Stderr *bool `yaml:"stderr"`
}

// IsDurable reports whether at least one durable sink (file, SQL or HTTP) is configured.
func (c Config) IsDurable() bool {
	return c.File != nil || c.SQL != nil || c.HTTP != nil
}

// New builds the Sink described by cfg. defaultWriter receives the stderr sink's output (pass
// os.Stderr or the context's stderr); it may be nil to disable that sink.
func New(cfg Config, defaultWriter io.Writer) (Sink, error) {
	var sinks []Sink
	if cfg.File != nil {
		sink, err := newFileSink(*cfg.File)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, sink)
	}
	if cfg.SQL != nil {
		sink, err := newSQLSink(*cfg.SQL, cfg.SQL.DSN)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, sink)
	}
	if cfg.HTTP != nil {
		sink, err := newHTTPSink(*cfg.HTTP, cfg.HTTP.Token)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, sink)
	}

	useStderr := len(sinks) == 0
	if cfg.Stderr != nil {
		useStderr = *cfg.Stderr
	}
	if useStderr && defaultWriter != nil {
		sinks = append(sinks, NewWriterSink(defaultWriter))
	}
	return Multi(sinks...), nil
}
