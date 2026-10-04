// Package unlock implements the vouched account-unlock workflow.
//
// The workflow has three steps, all made from one browser session:
//
//  1. Voucher: an authorised colleague signs in. They must be in a voucher group. This starts
//     the session, bound to their browser.
//  2. Claim: the locked-out user gives their username and password in that session. If binding
//     as them says the account is locked, and it is eligible for self-service unlock, the
//     password is held in memory and the user's details are shown to the voucher.
//  3. Confirm: the voucher attests they are with the user in person and re-enters their own
//     credentials. The account is unlocked and the password from step 2 is verified by binding
//     as the user.
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
	// given in step 2 turns out to be wrong.
	DisableOnFailedVerification bool `yaml:"disableOnFailedVerification"`
	// SessionLifetime is how long the whole workflow may take from the voucher signing in.
	SessionLifetime time.Duration `yaml:"sessionLifetime"`
	// ConfirmWindow is how long the voucher has to confirm after the user enters their details.
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
	StageAwaitingClaim        Stage = "awaiting_claim"
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
	// password is the claimant's password, held from step 2 until step 3 and then wiped.
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
		Target:          s.target,
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

// dropClaim discards the claimant so they must enter their details again. mu must be held.
func (s *session) dropClaim() {
	s.wipe()
	s.stage = StageAwaitingClaim
	s.claimedUsername = ""
	s.target = nil
	s.confirmBy = time.Time{}
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
	fields := []zap.Field{
		zap.String("audit_id", sess.auditID),
		zap.String("client_ip", sess.client.IP),
	}
	if sess.voucher != nil {
		fields = append(fields, zap.String("voucher_dn", sess.voucher.DN))
	}
	if sess.target != nil {
		fields = append(fields, zap.String("target_dn", sess.target.DN))
	}
	return logutil.FromCtx(ctx).Named("audit").With(fields...)
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

// authenticateVoucher looks up and binds as a voucher, and checks they are in a voucher group.
// log must already identify the session.
func (s *Service) authenticateVoucher(ctx context.Context, log *zap.Logger, client Client,
	username, password string,
) (*directory.User, error) {
	keys := rateKeys(client, username)
	if !s.limiter.Allowed(keys...) {
		log.Warn("Voucher rate limited", zap.String("voucher_username", username))
		return nil, errRateLimited()
	}
	voucher, err := s.dir.LookupUser(ctx, username)
	if errors.Is(err, directory.ErrUserNotFound) {
		log.Info("Voucher rejected: unknown user", zap.String("voucher_username", username))
		s.limiter.Fail(keys...)
		return nil, errInvalidCredentials()
	}
	if err != nil {
		log.Error("Voucher failed: directory lookup error", zap.Error(err))
		return nil, directoryError(err)
	}
	log = log.With(zap.String("voucher_username", voucher.SAMAccountName), zap.String("voucher_dn", voucher.DN))
	keys = append(keys, dnRateKey(voucher))
	if !s.limiter.Allowed(keys...) {
		log.Warn("Voucher rate limited")
		return nil, errRateLimited()
	}

	result, err := s.dir.Authenticate(ctx, voucher, []byte(password))
	if err != nil {
		log.Error("Voucher failed: directory bind error", zap.Error(err))
		return nil, directoryError(err)
	}
	if result != directory.BindOK {
		log.Info("Voucher rejected: sign-in failed", zap.String("bind_result", result.String()))
		s.limiter.Fail(keys...)
		return nil, errInvalidCredentials()
	}

	authorised, err := s.dir.IsMemberOfAny(ctx, voucher, s.policy.VoucherGroups)
	if err != nil {
		log.Error("Voucher failed: group membership lookup error", zap.Error(err))
		return nil, directoryError(err)
	}
	if !authorised {
		log.Warn("Voucher rejected: not in a voucher group")
		s.limiter.Fail(keys...)
		return nil, newError(CodeVoucherNotAuthorised, "Your account isn't allowed to vouch for other users.")
	}
	return voucher, nil
}

// StartVouch is step 1: an authorised colleague signs in, which starts a session. It returns
// the new session's ID.
func (s *Service) StartVouch(ctx context.Context, client Client, username, password string) (State, string, error) {
	username = directory.NormaliseUsername(username)
	if username == "" || password == "" {
		return State{Stage: StageStart}, "", newError(CodeBadRequest, "Enter your username and password.")
	}
	sess := &session{
		auditID:   randomID(9),
		client:    client,
		stage:     StageAwaitingClaim,
		expiresAt: s.now().Add(s.policy.SessionLifetime),
	}
	voucher, err := s.authenticateVoucher(ctx, auditLog(ctx, sess), client, username, password)
	if err != nil {
		return State{Stage: StageStart}, "", err
	}
	sess.voucher = voucher

	sessionID := randomID(32)
	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.mu.Unlock()
	auditLog(ctx, sess).Info("Voucher signed in, waiting for the locked-out user")

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

// Claim is step 2: the locked-out user enters their username and password. If the password
// works the account isn't locked, and the session completes.
func (s *Service) Claim(ctx context.Context, sessionID string, client Client, username, password string) (State, error) {
	sess, err := s.acquire(ctx, sessionID, client)
	if err != nil {
		return State{Stage: StageStart}, err
	}
	defer sess.mu.Unlock()
	if sess.stage != StageAwaitingClaim {
		return sess.state(), errWrongStage()
	}

	username = directory.NormaliseUsername(username)
	if username == "" || password == "" {
		return sess.state(), newError(CodeBadRequest, "Enter your username and password.")
	}
	log := auditLog(ctx, sess).With(zap.String("claimed_username", username))
	keys := rateKeys(client, username)
	if !s.limiter.Allowed(keys...) {
		log.Warn("Claim rate limited")
		return sess.state(), errRateLimited()
	}

	user, err := s.dir.LookupUser(ctx, username)
	if errors.Is(err, directory.ErrUserNotFound) {
		log.Info("Claim rejected: unknown user")
		s.limiter.Fail(keys...)
		return sess.state(), errInvalidCredentials()
	}
	if err != nil {
		log.Error("Claim failed: directory lookup error", zap.Error(err))
		return sess.state(), directoryError(err)
	}
	log = log.With(zap.String("target_dn", user.DN))

	if user.SameAs(sess.voucher) {
		log.Warn("Claim rejected: voucher tried to vouch for themselves")
		return sess.state(), newError(CodeVoucherIsClaimant,
			"You can't vouch for yourself. The locked-out user must enter their own details.")
	}
	// The same account can be named several ways, so limit by the account too.
	keys = append(keys, dnRateKey(user))
	if !s.limiter.Allowed(keys...) {
		log.Warn("Claim rate limited")
		return sess.state(), errRateLimited()
	}

	result, err := s.dir.Authenticate(ctx, user, []byte(password))
	if err != nil {
		log.Error("Claim failed: directory bind error", zap.Error(err))
		return sess.state(), directoryError(err)
	}
	log = log.With(zap.String("bind_result", result.String()))

	switch result {
	case directory.BindOK:
		log.Info("Claim: account is not locked")
		sess.claimedUsername = username
		sess.target = user
		sess.finish(OutcomeNotLocked, "This account's password works and it isn't locked. "+
			"The user can sign in normally.")
		return sess.state(), nil
	case directory.BindLockedOut:
		// Handled below.
	case directory.BindInvalidCredentials:
		log.Info("Claim rejected: invalid credentials")
		s.limiter.Fail(keys...)
		return sess.state(), errInvalidCredentials()
	case directory.BindPasswordExpired:
		log.Info("Claim rejected: password expired")
		return sess.state(), newError(CodeAccountRestricted,
			"This account isn't locked, but its password has expired. Change it the usual way, "+
				"or contact the service desk.")
	default:
		log.Info("Claim rejected: account restricted")
		return sess.state(), newError(CodeAccountRestricted,
			"This account can't be unlocked here. Please contact the service desk.")
	}

	sess.claimedUsername = username
	sess.target = user
	reason, err := s.checkEligible(ctx, user)
	if err != nil {
		log.Error("Claim failed: eligibility lookup error", zap.Error(err))
		sess.target = nil
		sess.claimedUsername = ""
		return sess.state(), directoryError(err)
	}
	if reason != "" {
		log.Warn("Target is not eligible for self-service unlock", zap.String("reason", reason))
		sess.finish(OutcomeIneligible, "This account can't be unlocked by self-service. Please contact the service desk.")
		return sess.state(), nil
	}

	sess.password = []byte(password)
	sess.stage = StageAwaitingConfirmation
	sess.confirmBy = s.now().Add(s.policy.ConfirmWindow)
	if sess.confirmBy.After(sess.expiresAt) {
		sess.confirmBy = sess.expiresAt
	}
	log.Info("Claim accepted: account is locked, waiting for the voucher to confirm",
		zap.Time("lockout_time", user.LockoutTime))
	return sess.state(), nil
}

// Confirm is step 3: the voucher attests to the claimant's identity and re-enters their own
// credentials. The account is unlocked and the claimant's password is verified.
func (s *Service) Confirm(ctx context.Context, sessionID string, client Client,
	username, password string, attest bool,
) (State, error) {
	sess, err := s.acquire(ctx, sessionID, client)
	if err != nil {
		return State{Stage: StageStart}, err
	}
	defer sess.mu.Unlock()
	if sess.stage != StageAwaitingConfirmation {
		return sess.state(), errWrongStage()
	}
	log := auditLog(ctx, sess)

	if !s.now().Before(sess.confirmBy) {
		log.Info("Confirmation window expired, the user must enter their details again")
		sess.dropClaim()
		return sess.state(), newError(CodeSessionExpired,
			"Too much time has passed. The locked-out user must enter their details again.")
	}
	if !attest {
		return sess.state(), newError(CodeAttestationRequired,
			"Confirm that you are with this person and have checked their identity.")
	}
	username = directory.NormaliseUsername(username)
	if username == "" || password == "" {
		return sess.state(), newError(CodeBadRequest, "Enter your username and password to confirm.")
	}

	// Check the name before binding, so a different account's password is never tried.
	if !strings.EqualFold(username, sess.voucher.SAMAccountName) &&
		!strings.EqualFold(username, sess.voucher.UserPrincipalName) {
		log.Warn("Confirmation rejected: a different voucher tried to confirm",
			zap.String("confirming_username", username))
		return sess.state(), errVoucherMismatch(sess.voucher)
	}
	voucher, err := s.authenticateVoucher(ctx, log, client, username, password)
	if err != nil {
		return sess.state(), err
	}
	if !voucher.SameAs(sess.voucher) {
		log.Warn("Confirmation rejected: signed in as a different voucher",
			zap.String("confirming_voucher_dn", voucher.DN))
		return sess.state(), errVoucherMismatch(sess.voucher)
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
		sess.finish(OutcomeUnlocked, "The account is unlocked. The user can sign in now.")
		return sess.state(), nil
	}

	s.limiter.Fail("ip:"+client.IP, dnRateKey(sess.target))
	message := "The account was unlocked, but the password the user entered was wrong. " +
		"If they've forgotten their password, contact the service desk to reset it."
	if s.policy.DisableOnFailedVerification {
		if err := s.dir.Disable(ctx, sess.target); err != nil {
			log.Error("Password verification failed after unlock, and disabling the account failed", zap.Error(err))
		} else {
			log.Warn("Password verification failed after unlock: account disabled")
			message = "The password the user entered was wrong, so the account has been disabled. " +
				"Contact the service desk."
		}
	} else {
		log.Warn("Password verification failed after unlock: account left unlocked")
	}
	sess.finish(OutcomeVerificationFailed, message)
	return sess.state(), nil
}
