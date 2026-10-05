package audit

import (
	"context"
	"errors"
	"io"
)

// multiSink fans an event out to several sinks. Because the unlock is gated on a committed
// audit record, Log fails if any sink fails: a quietly dropped record would defeat the gate.
type multiSink struct {
	sinks []Sink
}

// Log implements Sink. It writes to every sink and returns the combined error if any failed.
// Every sink is attempted even if an earlier one fails, so the others still record the event.
func (m *multiSink) Log(ctx context.Context, e Event) error {
	var errs []error
	for _, sink := range m.sinks {
		if err := sink.Log(ctx, e); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close implements Sink.
func (m *multiSink) Close() error {
	var errs []error
	for _, sink := range m.sinks {
		if closer, ok := sink.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// Multi returns a Sink that writes to all of sinks, failing if any one fails. With no sinks it
// returns Nop.
func Multi(sinks ...Sink) Sink {
	switch len(sinks) {
	case 0:
		return Nop{}
	case 1:
		return sinks[0]
	default:
		return &multiSink{sinks: sinks}
	}
}
