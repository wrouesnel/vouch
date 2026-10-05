package unlock_test

import (
	"context"
	"errors"
	"sync"

	"github.com/wrouesnel/vouch/pkg/audit"
)

// fakeSink records audit events and can be made to fail, to exercise the unlock gate.
type fakeSink struct {
	mu        sync.Mutex
	events    []audit.Event
	failTypes map[string]bool
	failAll   bool
}

func newFakeSink() *fakeSink {
	return &fakeSink{failTypes: map[string]bool{}}
}

func (f *fakeSink) Log(_ context.Context, e audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll || f.failTypes[e.Type] {
		return errors.New("audit sink unavailable")
	}
	f.events = append(f.events, e)
	return nil
}

func (f *fakeSink) Close() error { return nil }

// find returns the first recorded event of the given type, or false.
func (f *fakeSink) find(eventType string) (audit.Event, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.events {
		if e.Type == eventType {
			return e, true
		}
	}
	return audit.Event{}, false
}

// has reports whether an event of the type was recorded.
func (f *fakeSink) has(eventType string) bool {
	_, ok := f.find(eventType)
	return ok
}
