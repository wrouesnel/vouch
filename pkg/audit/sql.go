package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// SQLConfig configures an SQL audit sink. The target table must already exist; see the README
// for the DDL. Supported drivers are "pgx"/"postgres" (PostgreSQL), "mysql" and "sqlite".
type SQLConfig struct {
	// Driver is the database/sql driver name.
	Driver string `yaml:"driver"`
	// DSN is the data source name (connection string).
	DSN string `yaml:"dsn"`
	// DSNFile is read for the DSN if DSN is empty, so credentials can be kept out of config.
	DSNFile string `yaml:"dsnFile"`
	// Table is the table events are inserted into. Default "vouch_audit".
	Table string `yaml:"table"`
}

// sqlColumns are the table's columns, in insert order.
//
//nolint:gochecknoglobals
var sqlColumns = []string{
	"event_time", "event_type", "decision", "reason", "session",
	"client_ip", "client_user_agent", "voucher", "voucher_dn",
	"target", "target_dn", "bind_result", "outcome", "message", "detail",
}

// sqlSink inserts one row per event.
type sqlSink struct {
	db    *sql.DB
	query string
}

// Log implements Sink.
func (s *sqlSink) Log(ctx context.Context, e Event) error {
	detail, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: encoding event: %w", err)
	}
	_, err = s.db.ExecContext(ctx, s.query,
		e.Time.UTC(), e.Type, e.Decision, e.Reason, e.Session,
		e.ClientIP, e.ClientUserAgent, e.Voucher, e.VoucherDN,
		e.Target, e.TargetDN, e.BindResult, e.Outcome, e.Message, string(detail))
	if err != nil {
		return fmt.Errorf("audit: inserting event: %w", err)
	}
	return nil
}

// Close implements Sink.
func (s *sqlSink) Close() error { return s.db.Close() }

// placeholders returns the n bind markers for the driver: $1.. for postgres, ? otherwise.
func placeholders(driver string, n int) string {
	marks := make([]string, n)
	dollar := driver == "pgx" || driver == "postgres" || driver == "pq"
	for i := range marks {
		if dollar {
			marks[i] = fmt.Sprintf("$%d", i+1)
		} else {
			marks[i] = "?"
		}
	}
	return strings.Join(marks, ", ")
}

// validIdentifier reports whether name is a safe SQL identifier, since it's interpolated into
// the statement rather than bound.
func validIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r == '_':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// openDB is overridable in tests. It opens and verifies the connection.
//
//nolint:gochecknoglobals
var openDB = func(driver, dsn string) (*sql.DB, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// newSQLSink connects to the database and prepares the insert.
func newSQLSink(cfg SQLConfig, dsn string) (Sink, error) {
	if cfg.Driver == "" {
		return nil, fmt.Errorf("audit: sql sink needs a driver")
	}
	if dsn == "" {
		return nil, fmt.Errorf("audit: sql sink needs a dsn")
	}
	table := cfg.Table
	if table == "" {
		table = "vouch_audit"
	}
	if !validIdentifier(table) {
		return nil, fmt.Errorf("audit: invalid table name %q", table)
	}
	db, err := openDB(cfg.Driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: connecting to database: %w", err)
	}
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		table, strings.Join(sqlColumns, ", "), placeholders(cfg.Driver, len(sqlColumns)))
	return &sqlSink{db: db, query: query}, nil
}
