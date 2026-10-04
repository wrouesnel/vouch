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
	clock  *clock
	client unlock.Client
	ctx    context.Context
}

func newFixture(t *testing.T, mutate ...func(*unlock.Policy)) *fixture {
	t.Helper()
	dir := directorytest.NewFake()
	dir.Add("alice", alicePass, staff)
	dir.Add("bob", bobPass, helpdesk, staff)
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
	svc, err := unlock.NewService(dir, policy, unlock.WithClock(clk.Now))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		dir: dir, svc: svc, clock: clk,
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

// claimAndVouch runs steps 1 and 2 for alice with bob vouching.
func (f *fixture) claimAndVouch(t *testing.T, password string) string {
	t.Helper()
	state, sessionID, err := f.svc.Claim(f.ctx, f.client, "alice", password)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if state.Stage != unlock.StageAwaitingVoucher || sessionID == "" {
		t.Fatalf("claim: got %+v", state)
	}
	if state.Target != nil {
		t.Fatal("target details must not be shown before a voucher signs in")
	}
	state, err = f.svc.Vouch(f.ctx, sessionID, f.client, "bob", bobPass)
	if err != nil {
		t.Fatalf("vouch: %v", err)
	}
	if state.Stage != unlock.StageAwaitingConfirmation || state.Target == nil || state.Target.SAMAccountName != "alice" {
		t.Fatalf("vouch: got %+v", state)
	}
	return sessionID
}

func TestHappyPath(t *testing.T) {
	f := newFixture(t)
	sessionID := f.claimAndVouch(t, alicePass)
	state, err := f.svc.Confirm(f.ctx, sessionID, f.client, true)
	if err != nil {
		t.Fatal(err)
	}
	if state.Stage != unlock.StageComplete || state.Outcome != unlock.OutcomeUnlocked {
		t.Fatalf("got %+v", state)
	}
	if f.dir.Get("alice").Locked {
		t.Fatal("alice should be unlocked")
	}
	// Replaying the confirmation does nothing.
	_, err = f.svc.Confirm(f.ctx, sessionID, f.client, true)
	wantCode(t, err, unlock.CodeWrongStage)
	if f.dir.Unlocks != 1 {
		t.Fatalf("unlocks: got %d, want 1", f.dir.Unlocks)
	}
}

func TestWrongPasswordIsOnlyDetectedAfterUnlock(t *testing.T) {
	f := newFixture(t)
	sessionID := f.claimAndVouch(t, "not-alices-password")
	state, err := f.svc.Confirm(f.ctx, sessionID, f.client, true)
	if err != nil {
		t.Fatal(err)
	}
	if state.Outcome != unlock.OutcomeVerificationFailed {
		t.Fatalf("got %+v", state)
	}
	if f.dir.Get("alice").User.Disabled() {
		t.Fatal("alice must not be disabled unless the policy says so")
	}
}

func TestDisableOnFailedVerification(t *testing.T) {
	f := newFixture(t, func(p *unlock.Policy) { p.DisableOnFailedVerification = true })
	sessionID := f.claimAndVouch(t, "not-alices-password")
	state, err := f.svc.Confirm(f.ctx, sessionID, f.client, true)
	if err != nil || state.Outcome != unlock.OutcomeVerificationFailed {
		t.Fatalf("got %+v, %v", state, err)
	}
	if !f.dir.Get("alice").User.Disabled() {
		t.Fatal("alice should be disabled")
	}
}

func TestClaimNotLocked(t *testing.T) {
	f := newFixture(t)
	state, sessionID, err := f.svc.Claim(f.ctx, f.client, "carol", "carol-password")
	if err != nil {
		t.Fatal(err)
	}
	if state.Outcome != unlock.OutcomeNotLocked || sessionID != "" {
		t.Fatalf("got %+v, session %q", state, sessionID)
	}
}

func TestClaimRejections(t *testing.T) {
	f := newFixture(t)
	_, _, err := f.svc.Claim(f.ctx, f.client, "carol", "wrong")
	wantCode(t, err, unlock.CodeInvalidCredentials)
	_, _, err = f.svc.Claim(f.ctx, f.client, "nobody", "whatever")
	wantCode(t, err, unlock.CodeInvalidCredentials)
	_, _, err = f.svc.Claim(f.ctx, f.client, "alice", "")
	wantCode(t, err, unlock.CodeBadRequest)

	f.dir.Err = errors.New("dc down")
	_, _, err = f.svc.Claim(f.ctx, f.client, "alice", alicePass)
	wantCode(t, err, unlock.CodeDirectoryError)
}

func TestVoucherRules(t *testing.T) {
	f := newFixture(t)
	_, sessionID, err := f.svc.Claim(f.ctx, f.client, "alice", alicePass)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.svc.Vouch(f.ctx, sessionID, f.client, "alice", alicePass)
	wantCode(t, err, unlock.CodeVoucherIsClaimant)
	_, err = f.svc.Vouch(f.ctx, sessionID, f.client, `EXAMPLE\ALICE`, alicePass)
	wantCode(t, err, unlock.CodeVoucherIsClaimant)
	_, err = f.svc.Vouch(f.ctx, sessionID, f.client, "carol", "carol-password")
	wantCode(t, err, unlock.CodeVoucherNotAuthorised)
	_, err = f.svc.Vouch(f.ctx, sessionID, f.client, "bob", "wrong")
	wantCode(t, err, unlock.CodeInvalidCredentials)

	// Rejected vouchers leave the session waiting for another.
	state, err := f.svc.State(f.ctx, sessionID, f.client)
	if err != nil || state.Stage != unlock.StageAwaitingVoucher {
		t.Fatalf("got %+v, %v", state, err)
	}
	if _, err := f.svc.Confirm(f.ctx, sessionID, f.client, true); err == nil {
		t.Fatal("confirm must not be possible before a voucher signs in")
	}
}

func TestProtectedTargetIsIneligible(t *testing.T) {
	f := newFixture(t)
	f.dir.Lock("root")
	_, sessionID, err := f.svc.Claim(f.ctx, f.client, "root", "root-password")
	if err != nil {
		t.Fatal(err)
	}
	state, err := f.svc.Vouch(f.ctx, sessionID, f.client, "bob", bobPass)
	if err != nil || state.Outcome != unlock.OutcomeIneligible {
		t.Fatalf("got %+v, %v", state, err)
	}
	if f.dir.Unlocks != 0 {
		t.Fatal("protected account must not be unlocked")
	}
}

func TestEligibleGroups(t *testing.T) {
	f := newFixture(t, func(p *unlock.Policy) { p.EligibleGroups = []string{"CN=Nobody,DC=example,DC=test"} })
	_, sessionID, err := f.svc.Claim(f.ctx, f.client, "alice", alicePass)
	if err != nil {
		t.Fatal(err)
	}
	state, err := f.svc.Vouch(f.ctx, sessionID, f.client, "bob", bobPass)
	if err != nil || state.Outcome != unlock.OutcomeIneligible {
		t.Fatalf("got %+v, %v", state, err)
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
			_, sessionID, err := f.svc.Claim(f.ctx, f.client, "alice", alicePass)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.svc.Vouch(f.ctx, sessionID, other, "bob", bobPass)
			wantCode(t, err, unlock.CodePresenceMismatch)
			// The session is destroyed, even for the original browser.
			_, err = f.svc.Vouch(f.ctx, sessionID, f.client, "bob", bobPass)
			wantCode(t, err, unlock.CodeNoSession)
		})
	}

	t.Run("address change allowed by policy", func(t *testing.T) {
		f := newFixture(t, func(p *unlock.Policy) { p.AllowClientIPChange = true })
		_, sessionID, err := f.svc.Claim(f.ctx, f.client, "alice", alicePass)
		if err != nil {
			t.Fatal(err)
		}
		moved := unlock.Client{IP: "198.51.100.7", UserAgent: f.client.UserAgent}
		if _, err := f.svc.Vouch(f.ctx, sessionID, moved, "bob", bobPass); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSessionExpiry(t *testing.T) {
	f := newFixture(t)
	_, sessionID, err := f.svc.Claim(f.ctx, f.client, "alice", alicePass)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(unlock.DefaultSessionLifetime)
	_, err = f.svc.Vouch(f.ctx, sessionID, f.client, "bob", bobPass)
	wantCode(t, err, unlock.CodeSessionExpired)
	state, err := f.svc.State(f.ctx, sessionID, f.client)
	if err != nil || state.Stage != unlock.StageStart {
		t.Fatalf("got %+v, %v", state, err)
	}
}

func TestConfirmWindow(t *testing.T) {
	f := newFixture(t)
	sessionID := f.claimAndVouch(t, alicePass)
	f.clock.Advance(unlock.DefaultConfirmWindow)
	_, err := f.svc.Confirm(f.ctx, sessionID, f.client, true)
	wantCode(t, err, unlock.CodeSessionExpired)

	// The voucher has to sign in again.
	state, err := f.svc.State(f.ctx, sessionID, f.client)
	if err != nil || state.Stage != unlock.StageAwaitingVoucher || state.Voucher != nil {
		t.Fatalf("got %+v, %v", state, err)
	}
	if _, err := f.svc.Vouch(f.ctx, sessionID, f.client, "bob", bobPass); err != nil {
		t.Fatal(err)
	}
	if state, err := f.svc.Confirm(f.ctx, sessionID, f.client, true); err != nil || state.Outcome != unlock.OutcomeUnlocked {
		t.Fatalf("got %+v, %v", state, err)
	}
}

func TestAttestationRequired(t *testing.T) {
	f := newFixture(t)
	sessionID := f.claimAndVouch(t, alicePass)
	_, err := f.svc.Confirm(f.ctx, sessionID, f.client, false)
	wantCode(t, err, unlock.CodeAttestationRequired)
	if f.dir.Unlocks != 0 {
		t.Fatal("must not unlock without attestation")
	}
}

func TestTargetChangedBeforeVouch(t *testing.T) {
	f := newFixture(t)
	_, sessionID, err := f.svc.Claim(f.ctx, f.client, "alice", alicePass)
	if err != nil {
		t.Fatal(err)
	}
	f.dir.Get("alice").User.UserAccountControl |= 0x2
	state, err := f.svc.Vouch(f.ctx, sessionID, f.client, "bob", bobPass)
	if err != nil || state.Outcome != unlock.OutcomeIneligible {
		t.Fatalf("disabled since claim: got %+v, %v", state, err)
	}
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t, func(p *unlock.Policy) { p.RateLimit = unlock.RateLimitConfig{Attempts: 2, Window: time.Minute} })
	for range 2 {
		_, _, err := f.svc.Claim(f.ctx, f.client, "carol", "wrong")
		wantCode(t, err, unlock.CodeInvalidCredentials)
	}
	_, _, err := f.svc.Claim(f.ctx, f.client, "carol", "carol-password")
	wantCode(t, err, unlock.CodeRateLimited)
	if f.dir.Binds["carol"] != 2 {
		t.Fatalf("rate-limited attempts must not reach the directory: %d binds", f.dir.Binds["carol"])
	}

	// A different address is still limited by username.
	other := unlock.Client{IP: "198.51.100.7", UserAgent: "x"}
	_, _, err = f.svc.Claim(f.ctx, other, "carol", "carol-password")
	wantCode(t, err, unlock.CodeRateLimited)

	// Naming the account differently doesn't get round the limit.
	third := unlock.Client{IP: "203.0.113.9", UserAgent: "x"}
	_, _, err = f.svc.Claim(f.ctx, third, "carol@example.test", "carol-password")
	wantCode(t, err, unlock.CodeRateLimited)

	f.clock.Advance(time.Minute + time.Second)
	if _, _, err := f.svc.Claim(f.ctx, f.client, "carol", "carol-password"); err != nil {
		t.Fatalf("limit should reset after the window: %v", err)
	}
}

func TestCancelAndSweep(t *testing.T) {
	f := newFixture(t)
	_, sessionID, err := f.svc.Claim(f.ctx, f.client, "alice", alicePass)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Cancel(f.ctx, sessionID)
	_, err = f.svc.Vouch(f.ctx, sessionID, f.client, "bob", bobPass)
	wantCode(t, err, unlock.CodeNoSession)

	_, sessionID, err = f.svc.Claim(f.ctx, f.client, "alice", alicePass)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(unlock.DefaultSessionLifetime)
	f.svc.Sweep()
	_, err = f.svc.Vouch(f.ctx, sessionID, f.client, "bob", bobPass)
	wantCode(t, err, unlock.CodeNoSession)
}

func TestPolicyRequiresVoucherGroups(t *testing.T) {
	if _, err := unlock.NewService(directorytest.NewFake(), unlock.Policy{}); err == nil {
		t.Fatal("a policy without voucher groups must be rejected")
	}
}

// Ensure the fake satisfies the interface.
var _ directory.Directory = (*directorytest.Fake)(nil)
