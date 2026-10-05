package unlock_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/wrouesnel/vouch/pkg/directory"
	"github.com/wrouesnel/vouch/pkg/directory/directorytest"
	"github.com/wrouesnel/vouch/pkg/unlock"
)

const (
	helpdesk  = "CN=Helpdesk,DC=example,DC=test"
	admins    = "CN=Domain Admins,DC=example,DC=test"
	staff     = "CN=Staff,DC=example,DC=test"
	alicePass = "alice-password"
	bobPass   = "bob-password"
)

// clock is a settable time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fixture struct {
	dir    *directorytest.Fake
	svc    *unlock.Service
	sink   *fakeSink
	clock  *clock
	client unlock.Client
	ctx    context.Context
}

func newFixture(t *testing.T, mutate ...func(*unlock.Policy)) *fixture {
	t.Helper()
	dir := directorytest.NewFake()
	dir.Add("alice", alicePass, staff)
	dir.Add("bob", bobPass, helpdesk, staff)
	dir.Add("dave", "dave-password", helpdesk, staff)
	dir.Add("carol", "carol-password", staff)
	dir.Add("root", "root-password", admins)
	dir.Lock("alice")

	policy := unlock.Policy{
		VoucherGroups:   []string{helpdesk},
		ProtectedGroups: []string{admins},
		RateLimit:       unlock.RateLimitConfig{Attempts: 100, Window: time.Minute},
	}
	for _, fn := range mutate {
		fn(&policy)
	}
	clk := &clock{now: time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)}
	sink := newFakeSink()
	svc, err := unlock.NewService(dir, policy, sink, unlock.WithClock(clk.Now))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		dir: dir, svc: svc, sink: sink, clock: clk,
		client: unlock.Client{IP: "192.0.2.10", UserAgent: "Browser/1.0"},
		ctx:    context.Background(),
	}
}

func wantCode(t *testing.T, err error, code unlock.Code) {
	t.Helper()
	var unlockErr *unlock.Error
	if !errors.As(err, &unlockErr) {
		t.Fatalf("got error %v, want code %s", err, code)
	}
	if unlockErr.Code != code {
		t.Fatalf("got code %s (%s), want %s", unlockErr.Code, unlockErr.Message, code)
	}
}

// start runs step 1 with bob as the voucher.
func (f *fixture) start(t *testing.T) string {
	t.Helper()
	state, sessionID, err := f.svc.StartVouch(f.ctx, f.client, "bob", bobPass)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if state.Stage != unlock.StageAwaitingClaim || sessionID == "" || state.Voucher == nil || state.Target != nil {
		t.Fatalf("start: got %+v", state)
	}
	return sessionID
}

// startAndClaim runs steps 1 and 2 for alice with bob vouching.
func (f *fixture) startAndClaim(t *testing.T, password string) string {
	t.Helper()
	sessionID := f.start(t)
	state, err := f.svc.Claim(f.ctx, sessionID, f.client, "alice", password)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if state.Stage != unlock.StageAwaitingConfirmation || state.Target == nil || state.Target.SAMAccountName != "alice" {
		t.Fatalf("claim: got %+v", state)
	}
	return sessionID
}

func (f *fixture) confirm(sessionID string) (unlock.State, error) {
	return f.svc.Confirm(f.ctx, sessionID, f.client, "bob", bobPass, true)
}

func TestHappyPath(t *testing.T) {
	f := newFixture(t)
	sessionID := f.startAndClaim(t, alicePass)

	// After the claim the account has been verified and re-locked, not left unlocked.
	if !f.dir.Get("alice").Locked {
		t.Fatal("alice should be re-locked after the claim, before confirmation")
	}
	if f.dir.Verifications != 1 || f.dir.Unlocks != 0 {
		t.Fatalf("verifications=%d unlocks=%d, want 1 and 0", f.dir.Verifications, f.dir.Unlocks)
	}

	state, err := f.confirm(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Stage != unlock.StageComplete || state.Outcome != unlock.OutcomeUnlocked {
		t.Fatalf("got %+v", state)
	}
	if f.dir.Get("alice").Locked {
		t.Fatal("alice should be unlocked after confirmation")
	}
	if f.dir.Unlocks != 1 {
		t.Fatalf("unlocks: got %d, want 1", f.dir.Unlocks)
	}
	// The unlock was authorised in the audit log before it happened.
	if !f.sink.has("unlock_authorized") || !f.sink.has("unlock") {
		t.Fatal("unlock should be audited")
	}

	// Replaying the confirmation does nothing.
	_, err = f.confirm(sessionID)
	wantCode(t, err, unlock.CodeWrongStage)
	if f.dir.Unlocks != 1 {
		t.Fatalf("unlocks: got %d, want 1", f.dir.Unlocks)
	}
}

func TestUnlockIsGatedOnAudit(t *testing.T) {
	f := newFixture(t)
	f.sink.failTypes["unlock_authorized"] = true
	sessionID := f.startAndClaim(t, alicePass)

	_, err := f.confirm(sessionID)
	wantCode(t, err, unlock.CodeAuditFailed)
	if f.dir.Unlocks != 0 {
		t.Fatal("the account must not be unlocked when the audit record can't be committed")
	}
	if f.dir.Get("alice").Locked != true {
		t.Fatal("alice should still be locked")
	}

	// With the sink healthy again, the same session can complete.
	f.sink.failTypes["unlock_authorized"] = false
	state, err := f.confirm(sessionID)
	if err != nil || state.Outcome != unlock.OutcomeUnlocked {
		t.Fatalf("got %+v, %v", state, err)
	}
	if f.dir.Unlocks != 1 {
		t.Fatalf("unlocks: got %d, want 1", f.dir.Unlocks)
	}
}

func TestClaimVerifiesWithoutLeavingUnlocked(t *testing.T) {
	f := newFixture(t)
	sessionID := f.start(t)

	// A wrong password at the claim leaves the account locked and lets the user retry.
	_, err := f.svc.Claim(f.ctx, sessionID, f.client, "alice", "wrong")
	wantCode(t, err, unlock.CodeInvalidCredentials)
	if !f.dir.Get("alice").Locked {
		t.Fatal("alice must stay locked after a wrong password")
	}
	state, err := f.svc.State(f.ctx, sessionID, f.client)
	if err != nil || state.Stage != unlock.StageAwaitingClaim {
		t.Fatalf("session should still be awaiting a claim: %+v, %v", state, err)
	}

	// The right password moves on, with the account re-locked.
	state, err = f.svc.Claim(f.ctx, sessionID, f.client, "alice", alicePass)
	if err != nil || state.Stage != unlock.StageAwaitingConfirmation {
		t.Fatalf("got %+v, %v", state, err)
	}
	if !f.dir.Get("alice").Locked {
		t.Fatal("alice should be re-locked after verification")
	}
	if f.dir.Unlocks != 0 {
		t.Fatal("no permanent unlock should happen at the claim")
	}
}

func TestRelockFailureDisablesAndStops(t *testing.T) {
	f := newFixture(t)
	f.dir.RelockErr = errors.New("re-lock impossible")
	sessionID := f.start(t)

	state, err := f.svc.Claim(f.ctx, sessionID, f.client, "alice", alicePass)
	if err != nil || state.Outcome != unlock.OutcomeIneligible {
		t.Fatalf("got %+v, %v", state, err)
	}
	if !f.dir.Get("alice").User.Disabled() {
		t.Fatal("alice should be disabled as a safeguard when re-lock fails")
	}
	if !f.sink.has("relock_failed") {
		t.Fatal("the re-lock failure should be audited")
	}
	if f.dir.Unlocks != 0 {
		t.Fatal("no permanent unlock should happen")
	}
}

func TestVoucherSignIn(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		username, password string
		code               unlock.Code
	}{
		{"carol", "carol-password", unlock.CodeVoucherNotAuthorised},
		{"bob", "wrong", unlock.CodeInvalidCredentials},
		{"nobody", "whatever", unlock.CodeInvalidCredentials},
		{"alice", alicePass, unlock.CodeInvalidCredentials}, // locked accounts can't vouch
		{"bob", "", unlock.CodeBadRequest},
	}
	for _, tc := range cases {
		state, sessionID, err := f.svc.StartVouch(f.ctx, f.client, tc.username, tc.password)
		wantCode(t, err, tc.code)
		if sessionID != "" || state.Stage != unlock.StageStart {
			t.Fatalf("%s: a failed sign-in must not start a session", tc.username)
		}
	}
	f.dir.Err = errors.New("dc down")
	_, _, err := f.svc.StartVouch(f.ctx, f.client, "bob", bobPass)
	wantCode(t, err, unlock.CodeDirectoryError)
}

func TestClaimOutcomes(t *testing.T) {
	f := newFixture(t)
	sessionID := f.start(t)

	_, err := f.svc.Claim(f.ctx, sessionID, f.client, "bob", bobPass)
	wantCode(t, err, unlock.CodeVoucherIsClaimant)
	_, err = f.svc.Claim(f.ctx, sessionID, f.client, "carol", "wrong")
	wantCode(t, err, unlock.CodeInvalidCredentials)
	_, err = f.svc.Claim(f.ctx, sessionID, f.client, "nobody", "whatever")
	wantCode(t, err, unlock.CodeInvalidCredentials)
	_, err = f.svc.Claim(f.ctx, sessionID, f.client, "alice", "")
	wantCode(t, err, unlock.CodeBadRequest)

	// Rejected claims leave the session waiting for the user.
	state, err := f.svc.State(f.ctx, sessionID, f.client)
	if err != nil || state.Stage != unlock.StageAwaitingClaim {
		t.Fatalf("got %+v, %v", state, err)
	}
	if _, err := f.confirm(sessionID); err == nil {
		t.Fatal("confirm must not be possible before a claim")
	}

	// An account whose password works isn't locked, so it isn't unlocked.
	state, err = f.svc.Claim(f.ctx, sessionID, f.client, "carol", "carol-password")
	if err != nil || state.Outcome != unlock.OutcomeNotLocked {
		t.Fatalf("got %+v, %v", state, err)
	}
	if f.dir.Verifications != 0 {
		t.Fatal("an unlocked account must never be unlocked-and-verified")
	}
}

func TestProtectedTargetIsIneligible(t *testing.T) {
	f := newFixture(t)
	f.dir.Lock("root")
	sessionID := f.start(t)
	state, err := f.svc.Claim(f.ctx, sessionID, f.client, "root", "root-password")
	if err != nil || state.Outcome != unlock.OutcomeIneligible {
		t.Fatalf("got %+v, %v", state, err)
	}
	if f.dir.Verifications != 0 || f.dir.Unlocks != 0 {
		t.Fatal("a protected account must never be unlocked, even briefly")
	}
}

func TestEligibleGroups(t *testing.T) {
	f := newFixture(t, func(p *unlock.Policy) { p.EligibleGroups = []string{"CN=Nobody,DC=example,DC=test"} })
	sessionID := f.start(t)
	state, err := f.svc.Claim(f.ctx, sessionID, f.client, "alice", alicePass)
	if err != nil || state.Outcome != unlock.OutcomeIneligible {
		t.Fatalf("got %+v, %v", state, err)
	}
	if f.dir.Verifications != 0 {
		t.Fatal("an ineligible account must not be unlocked to verify")
	}
}

func TestDisabledTargetIsIneligible(t *testing.T) {
	f := newFixture(t)
	f.dir.Get("alice").User.UserAccountControl |= 0x2
	sessionID := f.start(t)
	state, err := f.svc.Claim(f.ctx, sessionID, f.client, "alice", alicePass)
	if err != nil || state.Outcome != unlock.OutcomeIneligible {
		t.Fatalf("got %+v, %v", state, err)
	}
}

func TestConfirmRequiresTheSameVoucher(t *testing.T) {
	f := newFixture(t)
	sessionID := f.startAndClaim(t, alicePass)

	_, err := f.svc.Confirm(f.ctx, sessionID, f.client, "bob", bobPass, false)
	wantCode(t, err, unlock.CodeAttestationRequired)

	// dave is a voucher too, but didn't start this session. His password is never tried.
	_, err = f.svc.Confirm(f.ctx, sessionID, f.client, "dave", "dave-password", true)
	wantCode(t, err, unlock.CodeVoucherMismatch)
	if f.dir.Binds["dave"] != 0 {
		t.Fatal("a mismatched voucher's password must not be tried")
	}

	_, err = f.svc.Confirm(f.ctx, sessionID, f.client, "bob", "wrong", true)
	wantCode(t, err, unlock.CodeInvalidCredentials)
	if f.dir.Unlocks != 0 {
		t.Fatal("must not unlock before the voucher re-authenticates")
	}

	// bob can retry, and may give his UPN instead.
	state, err := f.svc.Confirm(f.ctx, sessionID, f.client, "bob@example.test", bobPass, true)
	if err != nil || state.Outcome != unlock.OutcomeUnlocked {
		t.Fatalf("got %+v, %v", state, err)
	}
}

func TestConfirmRechecksVoucherGroups(t *testing.T) {
	f := newFixture(t)
	sessionID := f.startAndClaim(t, alicePass)
	f.dir.Get("bob").Groups = nil
	_, err := f.confirm(sessionID)
	wantCode(t, err, unlock.CodeVoucherNotAuthorised)
	if f.dir.Unlocks != 0 {
		t.Fatal("must not unlock for a voucher who lost their rights")
	}
}

func TestPresenceEnforcement(t *testing.T) {
	cases := map[string]unlock.Client{
		"different address": {IP: "198.51.100.7", UserAgent: "Browser/1.0"},
		"different browser": {IP: "192.0.2.10", UserAgent: "OtherBrowser/2.0"},
	}
	for name, other := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			sessionID := f.start(t)
			_, err := f.svc.Claim(f.ctx, sessionID, other, "alice", alicePass)
			wantCode(t, err, unlock.CodePresenceMismatch)
			if !f.sink.has("presence_mismatch") {
				t.Fatal("a presence mismatch should be audited")
			}
			// The session is destroyed, even for the original browser.
			_, err = f.svc.Claim(f.ctx, sessionID, f.client, "alice", alicePass)
			wantCode(t, err, unlock.CodeNoSession)
		})
	}

	t.Run("address change allowed by policy", func(t *testing.T) {
		f := newFixture(t, func(p *unlock.Policy) { p.AllowClientIPChange = true })
		sessionID := f.start(t)
		moved := unlock.Client{IP: "198.51.100.7", UserAgent: f.client.UserAgent}
		if _, err := f.svc.Claim(f.ctx, sessionID, moved, "alice", alicePass); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSessionExpiry(t *testing.T) {
	f := newFixture(t)
	sessionID := f.start(t)
	f.clock.Advance(unlock.DefaultSessionLifetime)
	_, err := f.svc.Claim(f.ctx, sessionID, f.client, "alice", alicePass)
	wantCode(t, err, unlock.CodeSessionExpired)
	state, err := f.svc.State(f.ctx, sessionID, f.client)
	if err != nil || state.Stage != unlock.StageStart {
		t.Fatalf("got %+v, %v", state, err)
	}
}

func TestConfirmWindow(t *testing.T) {
	f := newFixture(t)
	sessionID := f.startAndClaim(t, alicePass)
	f.clock.Advance(unlock.DefaultConfirmWindow)
	_, err := f.confirm(sessionID)
	wantCode(t, err, unlock.CodeSessionExpired)

	// The user has to enter their details again; the voucher stays signed in.
	state, err := f.svc.State(f.ctx, sessionID, f.client)
	if err != nil || state.Stage != unlock.StageAwaitingClaim || state.Target != nil || state.Voucher == nil {
		t.Fatalf("got %+v, %v", state, err)
	}
	if _, err := f.svc.Claim(f.ctx, sessionID, f.client, "alice", alicePass); err != nil {
		t.Fatal(err)
	}
	if state, err := f.confirm(sessionID); err != nil || state.Outcome != unlock.OutcomeUnlocked {
		t.Fatalf("got %+v, %v", state, err)
	}
}

func TestRateLimitCountsFailuresOnly(t *testing.T) {
	f := newFixture(t, func(p *unlock.Policy) { p.RateLimit = unlock.RateLimitConfig{Attempts: 2, Window: time.Minute} })

	// Successful unlocks don't count, so a service desk machine can do many in a row.
	for range 4 {
		f.dir.Lock("alice")
		sessionID := f.startAndClaim(t, alicePass)
		if state, err := f.confirm(sessionID); err != nil || state.Outcome != unlock.OutcomeUnlocked {
			t.Fatalf("got %+v, %v", state, err)
		}
	}

	sessionID := f.start(t)
	for range 2 {
		_, err := f.svc.Claim(f.ctx, sessionID, f.client, "carol", "wrong")
		wantCode(t, err, unlock.CodeInvalidCredentials)
	}
	_, err := f.svc.Claim(f.ctx, sessionID, f.client, "carol", "carol-password")
	wantCode(t, err, unlock.CodeRateLimited)
	if f.dir.Binds["carol"] != 2 {
		t.Fatalf("rate-limited attempts must not reach the directory: %d binds", f.dir.Binds["carol"])
	}

	// Another machine is still limited by the account, however it is named.
	other := unlock.Client{IP: "198.51.100.7", UserAgent: "x"}
	_, otherSession, err := f.svc.StartVouch(f.ctx, other, "bob", bobPass)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.Claim(f.ctx, otherSession, other, "carol@example.test", "carol-password")
	wantCode(t, err, unlock.CodeRateLimited)

	f.clock.Advance(time.Minute + time.Second)
	if state, err := f.svc.Claim(f.ctx, sessionID, f.client, "carol", "carol-password"); err != nil ||
		state.Outcome != unlock.OutcomeNotLocked {
		t.Fatalf("limit should reset after the window: %+v, %v", state, err)
	}
}

func TestCancelAndSweep(t *testing.T) {
	f := newFixture(t)
	sessionID := f.start(t)
	f.svc.Cancel(f.ctx, sessionID)
	if !f.sink.has("session_cancelled") {
		t.Fatal("a cancellation should be audited")
	}
	_, err := f.svc.Claim(f.ctx, sessionID, f.client, "alice", alicePass)
	wantCode(t, err, unlock.CodeNoSession)

	sessionID = f.start(t)
	f.clock.Advance(unlock.DefaultSessionLifetime)
	f.svc.Sweep()
	_, err = f.svc.Claim(f.ctx, sessionID, f.client, "alice", alicePass)
	wantCode(t, err, unlock.CodeNoSession)
}

func TestAuditTrailFields(t *testing.T) {
	f := newFixture(t)
	sessionID := f.startAndClaim(t, alicePass)
	if _, err := f.confirm(sessionID); err != nil {
		t.Fatal(err)
	}
	e, ok := f.sink.find("unlock_authorized")
	if !ok {
		t.Fatal("no unlock_authorized event")
	}
	if e.Target != "alice" || e.Voucher != "bob" || e.ClientIP != f.client.IP || e.Session == "" {
		t.Fatalf("event missing fields: %+v", e)
	}
}

func TestPolicyRequiresVoucherGroups(t *testing.T) {
	if _, err := unlock.NewService(directorytest.NewFake(), unlock.Policy{}, nil); err == nil {
		t.Fatal("a policy without voucher groups must be rejected")
	}
}

// Ensure the fake satisfies the interface.
var _ directory.Directory = (*directorytest.Fake)(nil)
