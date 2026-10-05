// Package audit records vouch's security-relevant actions to durable, tamper-evident sinks:
// a local file, an SQL database and/or an HTTP endpoint such as Splunk HEC.
//
// The account unlock is gated on a committed audit record: the service writes the
// authorisation event with Sink.Log and only unlocks the account if that returns nil. A sink's
// Log must therefore not return until the event is durably committed (flushed to disk, the row
// committed, the HTTP request acknowledged), and must return an error if it can't be.
package audit

import (
	"context"
	"time"
)

// Event is one audited action. Fields that don't apply to an event are left empty.
type Event struct {
	// Time is when the event occurred.
	Time time.Time `json:"time"`
	// Type names the event, e.g. "voucher_signin" or "unlock_authorized".
	Type string `json:"type"`
	// Decision is the security decision: "allow", "deny", "attempt", "success" or "failure".
	Decision string `json:"decision"`
	// Reason explains a denial or failure.
	Reason string `json:"reason,omitempty"`
	// Session is the per-session audit id. It is not the secret session cookie.
	Session string `json:"session,omitempty"`
	// ClientIP and ClientUserAgent identify the browser.
	ClientIP        string `json:"client_ip,omitempty"`
	ClientUserAgent string `json:"client_user_agent,omitempty"`
	// Voucher and VoucherDN identify the vouching colleague.
	Voucher   string `json:"voucher,omitempty"`
	VoucherDN string `json:"voucher_dn,omitempty"`
	// Target and TargetDN identify the account being unlocked.
	Target   string `json:"target,omitempty"`
	TargetDN string `json:"target_dn,omitempty"`
	// BindResult is the directory's classification of a password check.
	BindResult string `json:"bind_result,omitempty"`
	// Outcome is the final outcome of a completed session.
	Outcome string `json:"outcome,omitempty"`
	// Message is a human-readable summary.
	Message string `json:"message,omitempty"`
}

// Decisions.
const (
	DecisionAllow   = "allow"
	DecisionDeny    = "deny"
	DecisionAttempt = "attempt"
	DecisionSuccess = "success"
	DecisionFailure = "failure"
)

// Sink commits audit events. Log must block until the event is durably committed, and return
// an error if it can't be. Implementations must be safe for concurrent use.
type Sink interface {
	Log(ctx context.Context, e Event) error
	Close() error
}

// Nop is a Sink that discards events. It's only for tests and places that must not audit.
type Nop struct{}

// Log implements Sink.
func (Nop) Log(context.Context, Event) error { return nil }

// Close implements Sink.
func (Nop) Close() error { return nil }
