// Package unlock implements the vouched account-unlock workflow.
//
// The workflow has three steps, all made from one browser session:
//
//  1. Claim: the locked-out user gives their username and password. If binding as them says
//     the account is locked, a session is started holding the password in memory.
//  2. Vouch: a colleague signs in on the same browser. They must be in a voucher group, must
//     not be the claimant, and the claimant must be eligible for self-service unlock.
//  3. Confirm: the colleague attests they are with the user in person. The account is
//     unlocked and the password from step 1 is verified by binding as the user.
//
// AD won't say whether a password is right while the account is locked, so the password can
// only be verified after the unlock, in step 3.
package unlock

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"

	logutil "github.com/wrouesnel/go.logutil"
	"github.com/wrouesnel/vouch/pkg/directory"
	"go.uber.org/zap"
)

// Defaults for Policy.
const (
	DefaultSessionLifetime = 5 * time.Minute
	DefaultConfirmWindow   = 2 * time.Minute
	DefaultRateAttempts    = 10
	DefaultRateWindow      = 15 * time.Minute
)

// Policy decides who may vouch, who may be unlocked, and how long each step may take.
type Policy struct {
	// VoucherGroups are the DNs of groups whose members, directly or through nested groups, may
	// vouch for another user. At least one is required.
	VoucherGroups []string `yaml:"voucherGroups"`
	// ProtectedGroups are the DNs of groups whose members may never be unlocked here, such as
	// Domain Admins.
	ProtectedGroups []string `yaml:"protectedGroups"`
	// EligibleGroups, if set, limits unlocking to members of these groups.
	EligibleGroups []string `yaml:"eligibleGroups"`
	// DisableOnFailedVerification disables an account if, after it was unlocked, the password
	// given in step 1 turns out to be wrong.
	DisableOnFailedVerification bool `yaml:"disableOnFailedVerification"`
	// SessionLifetime is how long the whole workflow may take from step 1.
	SessionLifetime time.Duration `yaml:"sessionLifetime"`
	// ConfirmWindow is how long the voucher has to confirm after signing in.
	ConfirmWindow time.Duration `yaml:"confirmWindow"`
	// AllowClientIPChange lets a session continue from a different client address. Leave it
	// off unless clients' addresses legitimately change mid-session.
	AllowClientIPChange bool `yaml:"allowClientIPChange"`
	// RateLimit caps attempts per client address and per username.
	RateLimit RateLimitConfig `yaml:"rateLimit"`
}

// Stage is where a session is in the workflow.
type Stage string

// Stages. These match the API.
const (
	StageStart                Stage = "start"
	StageAwaitingVoucher      Stage = "awaiting_voucher"
	StageAwaitingConfirmation Stage = "awaiting_confirmation"
	StageComplete             Stage = "complete"
)

// Outcome is how a completed session ended. These match the API.
type Outcome string

// Outcomes.
const (
	OutcomeNone               Outcome = ""
	OutcomeNotLocked          Outcome = "not_locked"
	OutcomeUnlocked           Outcome = "unlocked"
	OutcomeVerificationFailed Outcome = "verification_failed"
	OutcomeIneligible         Outcome = "ineligible"
)

// Client identifies the browser making a request.
type Client struct {
	IP        string
	UserAgent string
}

// State is a snapshot of a session for display.
type State struct {
	Stage           Stage
	ClaimedUsername string
	Target          *directory.User
	Voucher         *directory.User
	Outcome         Outcome
	Message         string
	ExpiresAt       time.Time
	ConfirmBy       time.Time
}

// session is one browser's progress through the workflow.
type session struct {
	mu sync.Mutex

	// auditID identifies the session in logs. The session ID is a secret and is never logged.
	auditID         string
	client          Client
	expiresAt       time.Time
	stage           Stage
	claimedUsername string
	target          *directory.User
	// password is the claimant's password, held until step 3 and then wiped.
	password  []byte
	voucher   *directory.User
	confirmBy time.Time
	outcome   Outcome
	message   string
}

// state returns a snapshot. mu must be held.
func (s *session) state() State {
	state := State{
		Stage:           s.stage,
		ClaimedUsername: s.claimedUsername,
		Outcome:         s.outcome,
		Message:         s.message,
		ExpiresAt:       s.expiresAt,
		Voucher:         s.voucher,
	}
	// The claimant's directory details are only shown once a voucher has signed in, so the
	// first step doesn't reveal anything about an account to whoever typed its name.
	if s.voucher != nil {
		state.Target = s.target
	}
	if s.stage == StageAwaitingConfirmation {
		state.ConfirmBy = s.confirmBy
	}
	return state
}

// wipe discards the claimant's password. mu must be held.
func (s *session) wipe() {
	for i := range s.password {
		s.password[i] = 0
	}
	s.password = nil
}

// finish moves the session to complete. mu must be held.
func (s *session) finish(outcome Outcome, message string) {
	s.wipe()
	s.stage = StageComplete
	s.outcome = outcome
	s.message = message
}

// Service runs the workflow.
type Service struct {
	dir     directory.Directory
	policy  Policy
	now     func() time.Time
	limiter *limiter

	mu       sync.Mutex
	sessions map[string]*session
}

// Option configures a Service.
type Option func(*Service)

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}

// NewService returns a Service. Unset durations in policy get their defaults.
func NewService(dir directory.Directory, policy Policy, opts ...Option) (*Service, error) {
	if len(policy.VoucherGroups) == 0 {
		return nil, errors.New("policy: at least one voucher group is required")
	}
	if policy.SessionLifetime <= 0 {
		policy.SessionLifetime = DefaultSessionLifetime
	}
	if policy.ConfirmWindow <= 0 {
		policy.ConfirmWindow = DefaultConfirmWindow
	}
	if policy.RateLimit.Attempts == 0 && policy.RateLimit.Window == 0 {
		policy.RateLimit = RateLimitConfig{Attempts: DefaultRateAttempts, Window: DefaultRateWindow}
	}
	svc := &Service{
		dir:      dir,
		policy:   policy,
		now:      time.Now,
		sessions: map[string]*session{},
	}
	for _, opt := range opts {
		opt(svc)
	}
	svc.limiter = newLimiter(policy.RateLimit, svc.now)
	return svc, nil
}

// Policy returns the effective policy, with defaults applied.
func (s *Service) Policy() Policy {
	return s.policy
}

// Run sweeps expired sessions, wiping any passwords they hold, until ctx is done.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			for id, sess := range s.sessions {
				sess.mu.Lock()
				sess.wipe()
				sess.mu.Unlock()
				delete(s.sessions, id)
			}
			s.mu.Unlock()
			return
		case <-ticker.C:
			s.Sweep()
		}
	}
}

// Sweep removes expired sessions and forgets stale rate limit entries.
func (s *Service) Sweep() {
	now := s.now()
	s.mu.Lock()
	for id, sess := range s.sessions {
		sess.mu.Lock()
		if !now.Before(sess.expiresAt) {
			sess.wipe()
			delete(s.sessions, id)
		}
		sess.mu.Unlock()
	}
	s.mu.Unlock()
	s.limiter.Sweep()
}

func randomID(size int) string {
	buf := make([]byte, size)
	_, _ = rand.Read(buf) // crypto/rand.Read never returns an error
	return base64.RawURLEncoding.EncodeToString(buf)
}

// auditLog returns the audit logger for a session.
func auditLog(ctx context.Context, sess *session) *zap.Logger {
	return logutil.FromCtx(ctx).Named("audit").With(
		zap.String("audit_id", sess.auditID),
		zap.String("client_ip", sess.client.IP),
		zap.String("claimed_username", sess.claimedUsername))
}

// remove deletes a session and wipes it.
func (s *Service) remove(sessionID string) {
	s.mu.Lock()
	sess, ok := s.sessions[sessionID]
	delete(s.sessions, sessionID)
	s.mu.Unlock()
	if ok {
		sess.mu.Lock()
		sess.wipe()
		sess.mu.Unlock()
	}
}

// acquire finds a live session made by client and returns it locked. A session from a
// different browser or address is destroyed.
func (s *Service) acquire(ctx context.Context, sessionID string, client Client) (*session, error) {
	if sessionID == "" {
		return nil, errNoSession()
	}
	s.mu.Lock()
	sess, ok := s.sessions[sessionID]
	s.mu.Unlock()
	if !ok {
		return nil, errNoSession()
	}
	sess.mu.Lock()
	if !s.now().Before(sess.expiresAt) {
		sess.mu.Unlock()
		s.remove(sessionID)
		return nil, errSessionExpired()
	}
	if sess.client.UserAgent != client.UserAgent ||
		(!s.policy.AllowClientIPChange && sess.client.IP != client.IP) {
		auditLog(ctx, sess).Warn("Session used from a different client - cancelling it",
			zap.String("request_ip", client.IP), zap.String("request_user_agent", client.UserAgent))
		sess.mu.Unlock()
		s.remove(sessionID)
		return nil, errPresenceMismatch()
	}
	return sess, nil
}

// rateKeys are the limiter keys for an attempt.
func rateKeys(client Client, username string) []string {
	return []string{"ip:" + client.IP, "user:" + strings.ToLower(directory.NormaliseUsername(username))}
}

// dnRateKey is the limiter key for a directory account, however it was named.
func dnRateKey(user *directory.User) string {
	return "dn:" + strings.ToLower(user.DN)
}

// State returns the state of a session. A missing or expired session is in StageStart.
func (s *Service) State(ctx context.Context, sessionID string, client Client) (State, error) {
	sess, err := s.acquire(ctx, sessionID, client)
	if err != nil {
		var unlockErr *Error
		if errors.As(err, &unlockErr) && (unlockErr.Code == CodeNoSession || unlockErr.Code == CodeSessionExpired) {
			return State{Stage: StageStart}, nil
		}
		return State{Stage: StageStart}, err
	}
	defer sess.mu.Unlock()
	return sess.state(), nil
}

// Cancel abandons a session.
func (s *Service) Cancel(ctx context.Context, sessionID string) {
	s.mu.Lock()
	sess, ok := s.sessions[sessionID]
	s.mu.Unlock()
	if ok {
		sess.mu.Lock()
		auditLog(ctx, sess).Info("Session cancelled", zap.String("stage", string(sess.stage)))
		sess.mu.Unlock()
		s.remove(sessionID)
	}
}

// Claim is step 1. If the account is locked it starts a session and returns its ID. If the
// password works the account isn't locked, and no session is started.
func (s *Service) Claim(ctx context.Context, client Client, username, password string) (State, string, error) {
	username = directory.NormaliseUsername(username)
	if username == "" || password == "" {
		return State{}, "", newError(CodeBadRequest, "Enter your username and password.")
	}
	if !s.limiter.Allow(rateKeys(client, username)...) {
		logutil.FromCtx(ctx).Named("audit").Warn("Claim rate limited",
			zap.String("client_ip", client.IP), zap.String("claimed_username", username))
		return State{}, "", errRateLimited()
	}

	sess := &session{
		auditID:         randomID(9),
		client:          client,
		claimedUsername: username,
		stage:           StageAwaitingVoucher,
		expiresAt:       s.now().Add(s.policy.SessionLifetime),
	}
	log := auditLog(ctx, sess)

	user, err := s.dir.LookupUser(ctx, username)
	if errors.Is(err, directory.ErrUserNotFound) {
		log.Info("Claim rejected: unknown user")
		return State{}, "", errInvalidCredentials()
	}
	if err != nil {
		log.Error("Claim failed: directory lookup error", zap.Error(err))
		return State{}, "", directoryError(err)
	}

	// The same account can be named several ways, so limit by the account too.
	if !s.limiter.Allow(dnRateKey(user)) {
		log.Warn("Claim rate limited", zap.String("target_dn", user.DN))
		return State{}, "", errRateLimited()
	}

	result, err := s.dir.Authenticate(ctx, user, []byte(password))
	if err != nil {
		log.Error("Claim failed: directory bind error", zap.Error(err))
		return State{}, "", directoryError(err)
	}
	log = log.With(zap.String("target_dn", user.DN), zap.String("bind_result", result.String()))

	switch result {
	case directory.BindOK:
		log.Info("Claim: account is not locked")
		return State{
			Stage:           StageComplete,
			ClaimedUsername: username,
			Outcome:         OutcomeNotLocked,
			Message:         "Your password works and your account isn't locked. You can sign in normally.",
		}, "", nil
	case directory.BindLockedOut:
		// Handled below.
	case directory.BindInvalidCredentials:
		log.Info("Claim rejected: invalid credentials")
		return State{}, "", errInvalidCredentials()
	case directory.BindPasswordExpired:
		log.Info("Claim rejected: password expired")
		return State{}, "", newError(CodeAccountRestricted,
			"Your account isn't locked, but your password has expired. Change it the usual way, "+
				"or contact the service desk.")
	default:
		log.Info("Claim rejected: account restricted")
		return State{}, "", newError(CodeAccountRestricted,
			"This account can't be unlocked here. Please contact the service desk.")
	}

	sess.target = user
	sess.password = []byte(password)
	sessionID := randomID(32)
	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.mu.Unlock()
	log.Info("Claim accepted: account is locked, waiting for a voucher",
		zap.Time("lockout_time", user.LockoutTime))

	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.state(), sessionID, nil
}

// checkEligible reports why target can't be unlocked, or "" if it can.
func (s *Service) checkEligible(ctx context.Context, target *directory.User) (string, error) {
	if target.Disabled() {
		return "disabled", nil
	}
	protected, err := s.dir.IsMemberOfAny(ctx, target, s.policy.ProtectedGroups)
	if err != nil {
		return "", err
	}
	if protected {
		return "member of a protected group", nil
	}
	if len(s.policy.EligibleGroups) > 0 {
		eligible, err := s.dir.IsMemberOfAny(ctx, target, s.policy.EligibleGroups)
		if err != nil {
			return "", err
		}
		if !eligible {
			return "not a member of an eligible group", nil
		}
	}
	return "", nil
}

// Vouch is step 2: a colleague signs in to vouch for the claimant.
func (s *Service) Vouch(ctx context.Context, sessionID string, client Client, username, password string) (State, error) {
	sess, err := s.acquire(ctx, sessionID, client)
	if err != nil {
		return State{Stage: StageStart}, err
	}
	defer sess.mu.Unlock()
	if sess.stage != StageAwaitingVoucher {
		return sess.state(), errWrongStage()
	}

	username = directory.NormaliseUsername(username)
	if username == "" || password == "" {
		return sess.state(), newError(CodeBadRequest, "Enter your username and password.")
	}
	log := auditLog(ctx, sess).With(zap.String("voucher_username", username))
	if !s.limiter.Allow(rateKeys(client, username)...) {
		log.Warn("Voucher rate limited")
		return sess.state(), errRateLimited()
	}

	voucher, err := s.dir.LookupUser(ctx, username)
	if errors.Is(err, directory.ErrUserNotFound) {
		log.Info("Voucher rejected: unknown user")
		return sess.state(), errInvalidCredentials()
	}
	if err != nil {
		log.Error("Voucher failed: directory lookup error", zap.Error(err))
		return sess.state(), directoryError(err)
	}
	log = log.With(zap.String("voucher_dn", voucher.DN))

	if voucher.SameAs(sess.target) {
		log.Warn("Voucher rejected: claimant tried to vouch for themselves")
		return sess.state(), newError(CodeVoucherIsClaimant,
			"You can't vouch for yourself. A colleague must sign in here.")
	}

	if !s.limiter.Allow(dnRateKey(voucher)) {
		log.Warn("Voucher rate limited")
		return sess.state(), errRateLimited()
	}

	result, err := s.dir.Authenticate(ctx, voucher, []byte(password))
	if err != nil {
		log.Error("Voucher failed: directory bind error", zap.Error(err))
		return sess.state(), directoryError(err)
	}
	if result != directory.BindOK {
		log.Info("Voucher rejected: sign-in failed", zap.String("bind_result", result.String()))
		return sess.state(), errInvalidCredentials()
	}

	authorised, err := s.dir.IsMemberOfAny(ctx, voucher, s.policy.VoucherGroups)
	if err != nil {
		log.Error("Voucher failed: group membership lookup error", zap.Error(err))
		return sess.state(), directoryError(err)
	}
	if !authorised {
		log.Warn("Voucher rejected: not in a voucher group")
		return sess.state(), newError(CodeVoucherNotAuthorised,
			"Your account isn't allowed to vouch for other users.")
	}

	// Re-read the target so the checks and the details shown to the voucher are current.
	target, err := s.dir.LookupDN(ctx, sess.target.DN)
	if errors.Is(err, directory.ErrUserNotFound) {
		log.Warn("Target disappeared since the claim")
		sess.finish(OutcomeIneligible, "This account changed while the request was in progress. Please start again.")
		return sess.state(), nil
	}
	if err != nil {
		log.Error("Voucher failed: target lookup error", zap.Error(err))
		return sess.state(), directoryError(err)
	}
	if !target.SameAs(sess.target) {
		log.Error("Voucher failed: target changed identity since the claim")
		sess.finish(OutcomeIneligible, "This account changed while the request was in progress. Please start again.")
		return sess.state(), nil
	}
	sess.target = target
	sess.voucher = voucher

	reason, err := s.checkEligible(ctx, target)
	if err != nil {
		log.Error("Voucher failed: eligibility lookup error", zap.Error(err))
		sess.voucher = nil
		return sess.state(), directoryError(err)
	}
	if reason != "" {
		log.Warn("Target is not eligible for self-service unlock", zap.String("reason", reason))
		sess.finish(OutcomeIneligible, "This account can't be unlocked by self-service. Please contact the service desk.")
		return sess.state(), nil
	}

	sess.stage = StageAwaitingConfirmation
	sess.confirmBy = s.now().Add(s.policy.ConfirmWindow)
	if sess.confirmBy.After(sess.expiresAt) {
		sess.confirmBy = sess.expiresAt
	}
	log.Info("Voucher accepted, waiting for confirmation")
	return sess.state(), nil
}

// Confirm is step 3: the voucher attests to the claimant's identity, the account is unlocked,
// and the claimant's password is verified.
func (s *Service) Confirm(ctx context.Context, sessionID string, client Client, attest bool) (State, error) {
	sess, err := s.acquire(ctx, sessionID, client)
	if err != nil {
		return State{Stage: StageStart}, err
	}
	defer sess.mu.Unlock()
	if sess.stage != StageAwaitingConfirmation {
		return sess.state(), errWrongStage()
	}
	log := auditLog(ctx, sess).With(
		zap.String("target_dn", sess.target.DN), zap.String("voucher_dn", sess.voucher.DN))

	if !s.now().Before(sess.confirmBy) {
		log.Info("Confirmation window expired, voucher must sign in again")
		sess.stage = StageAwaitingVoucher
		sess.voucher = nil
		return sess.state(), newError(CodeSessionExpired,
			"The voucher's sign-in has expired. Please sign in again to vouch.")
	}
	if !attest {
		return sess.state(), newError(CodeAttestationRequired,
			"Confirm that you are with this person and have checked their identity.")
	}

	result, err := s.dir.UnlockAndVerify(ctx, sess.target, sess.password)
	sess.wipe()
	if err != nil {
		log.Error("Unlock failed", zap.Error(err))
		sess.finish(OutcomeNone, "")
		return sess.state(), directoryError(err)
	}
	log = log.With(zap.String("bind_result", result.String()))

	if result == directory.BindOK {
		log.Info("Account unlocked and password verified")
		sess.finish(OutcomeUnlocked, "The account is unlocked. You can sign in now.")
		return sess.state(), nil
	}

	message := "The account was unlocked, but the password entered in the first step was wrong. " +
		"If you've forgotten your password, contact the service desk to reset it."
	if s.policy.DisableOnFailedVerification {
		if err := s.dir.Disable(ctx, sess.target); err != nil {
			log.Error("Password verification failed after unlock, and disabling the account failed", zap.Error(err))
		} else {
			log.Warn("Password verification failed after unlock: account disabled")
			message = "The password entered in the first step was wrong, so the account has been disabled. " +
				"Contact the service desk."
		}
	} else {
		log.Warn("Password verification failed after unlock: account left unlocked")
	}
	sess.finish(OutcomeVerificationFailed, message)
	return sess.state(), nil
}
