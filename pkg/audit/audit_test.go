package audit_test

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/wrouesnel/vouch/pkg/audit"
)

func sampleEvent() audit.Event {
	return audit.Event{
		Time: time.Date(2026, 2, 3, 10, 30, 0, 0, time.UTC),
		Type: "unlock_authorized", Decision: audit.DecisionAllow,
		Session: "abc", ClientIP: "192.0.2.1", Voucher: "bob", Target: "alice",
		Message: "ok",
	}
}

func TestFileSinkWritesJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := audit.New(audit.Config{File: &audit.FileConfig{Path: path}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := sink.Log(context.Background(), sampleEvent()); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	lines := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var e audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("line %d is not JSON: %v", lines, err)
		}
		if e.Type != "unlock_authorized" || e.Target != "alice" {
			t.Fatalf("unexpected event: %+v", e)
		}
		lines++
	}
	if lines != 3 {
		t.Fatalf("got %d lines, want 3", lines)
	}
}

// countingSink records calls and can be made to fail.
type countingSink struct {
	mu    sync.Mutex
	count int
	fail  bool
}

func (c *countingSink) Log(context.Context, audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	if c.fail {
		return errors.New("down")
	}
	return nil
}
func (c *countingSink) Close() error { return nil }

func TestMultiFailsIfAnySinkFails(t *testing.T) {
	ok := &countingSink{}
	bad := &countingSink{fail: true}
	sink := audit.Multi(ok, bad)

	err := sink.Log(context.Background(), sampleEvent())
	if err == nil {
		t.Fatal("Multi.Log should fail when a sink fails")
	}
	// Every sink is still attempted, so the healthy one has the record.
	if ok.count != 1 || bad.count != 1 {
		t.Fatalf("counts: ok=%d bad=%d", ok.count, bad.count)
	}
}

func TestHTTPSinkSplunk(t *testing.T) {
	var got struct {
		auth string
		body []byte
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.auth = r.Header.Get("Authorization")
		got.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := audit.New(audit.Config{HTTP: &audit.HTTPConfig{
		URL: server.URL, Splunk: true, Token: "secret-token",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Log(context.Background(), sampleEvent()); err != nil {
		t.Fatal(err)
	}
	if got.auth != "Splunk secret-token" {
		t.Fatalf("auth header: %q", got.auth)
	}
	var envelope struct {
		Event audit.Event `json:"event"`
	}
	if err := json.Unmarshal(got.body, &envelope); err != nil {
		t.Fatalf("body not a Splunk envelope: %v (%s)", err, got.body)
	}
	if envelope.Event.Target != "alice" {
		t.Fatalf("wrapped event: %+v", envelope.Event)
	}
}

func TestHTTPSinkRetriesThenFails(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	sink, err := audit.New(audit.Config{HTTP: &audit.HTTPConfig{
		URL: server.URL, Retries: 2, Timeout: time.Second,
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Log(context.Background(), sampleEvent()); err == nil {
		t.Fatal("a 500 should fail the sink")
	}
	if calls.Load() != 3 { // initial + 2 retries
		t.Fatalf("got %d attempts, want 3", calls.Load())
	}
}

func TestSQLSinkInsertsRow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE vouch_audit (
		event_time TEXT, event_type TEXT, decision TEXT, reason TEXT, session TEXT,
		client_ip TEXT, client_user_agent TEXT, voucher TEXT, voucher_dn TEXT,
		target TEXT, target_dn TEXT, bind_result TEXT, outcome TEXT, message TEXT, detail TEXT)`)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	sink, err := audit.New(audit.Config{SQL: &audit.SQLConfig{Driver: "sqlite", DSN: path}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Log(context.Background(), sampleEvent()); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var eventType, target, detail string
	row := db.QueryRow("SELECT event_type, target, detail FROM vouch_audit")
	if err := row.Scan(&eventType, &target, &detail); err != nil {
		t.Fatal(err)
	}
	if eventType != "unlock_authorized" || target != "alice" {
		t.Fatalf("row: type=%q target=%q", eventType, target)
	}
	var e audit.Event
	if err := json.Unmarshal([]byte(detail), &e); err != nil || e.Voucher != "bob" {
		t.Fatalf("detail column: %v %q", err, detail)
	}
}

func TestSQLSinkRejectsBadTable(t *testing.T) {
	_, err := audit.New(audit.Config{SQL: &audit.SQLConfig{
		Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "x.db"), Table: "bad; DROP TABLE",
	}}, nil)
	if err == nil {
		t.Fatal("an invalid table name must be rejected")
	}
}

func TestDefaultsToWriterWhenNoDurableSink(t *testing.T) {
	cfg := audit.Config{}
	if cfg.IsDurable() {
		t.Fatal("empty config should not be durable")
	}
	buf := &syncBuffer{}
	sink, err := audit.New(cfg, buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Log(context.Background(), sampleEvent()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("event should have been written to the default writer")
	}
}

// syncBuffer is a minimal concurrency-safe buffer.
type syncBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buf)
}
