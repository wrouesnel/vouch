package directory

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	logutil "github.com/wrouesnel/go.logutil"
	"go.uber.org/zap"
)

// DefaultUserFilter matches a person by sAMAccountName or userPrincipalName. {username} is
// replaced by the escaped username.
const DefaultUserFilter = "(&(objectCategory=person)(objectClass=user)" +
	"(|(sAMAccountName={username})(userPrincipalName={username})))"

// DefaultTimeout bounds each LDAP connection and operation.
const DefaultTimeout = 10 * time.Second

// matchingRuleInChain is LDAP_MATCHING_RULE_IN_CHAIN, which makes AD follow nested group
// membership when evaluating a memberOf filter.
const matchingRuleInChain = "1.2.840.113556.1.4.1941"

// Config configures the connection to Active Directory.
type Config struct {
	// URLs of domain controllers, tried in order, e.g. ldaps://dc1.example.com.
	URLs []string `yaml:"urls"`
	// StartTLS upgrades ldap:// connections with StartTLS.
	StartTLS bool `yaml:"startTLS"`
	// CAFile is a PEM bundle of CAs to trust instead of the system pool.
	CAFile string `yaml:"caFile"`
	// InsecureSkipVerify disables TLS certificate checks. For testing only.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
	// Timeout bounds each connection and operation.
	Timeout time.Duration `yaml:"timeout"`
	// BaseDN is where users are searched for.
	BaseDN string `yaml:"baseDN"`
	// BindDN is the service account used to search and unlock.
	BindDN string `yaml:"bindDN"`
	// BindPassword is the service account's password.
	BindPassword string `yaml:"bindPassword"`
	// BindPasswordFile is read for the service account's password if BindPassword is empty.
	BindPasswordFile string `yaml:"bindPasswordFile"`
	// UserFilter finds a user. {username} is replaced by the escaped username.
	UserFilter string `yaml:"userFilter"`
}

// LDAP implements Directory against Active Directory.
type LDAP struct {
	cfg     Config
	rootCAs *x509.CertPool
}

// NewLDAP returns a Directory for cfg. rootCAs may be nil to use the system pool.
func NewLDAP(cfg Config, rootCAs *x509.CertPool) (*LDAP, error) {
	if len(cfg.URLs) == 0 {
		return nil, errors.New("directory: no urls configured")
	}
	for _, rawURL := range cfg.URLs {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("directory: bad url %q: %w", rawURL, err)
		}
		if parsed.Scheme != "ldap" && parsed.Scheme != "ldaps" {
			return nil, fmt.Errorf("directory: url %q must be ldap:// or ldaps://", rawURL)
		}
	}
	if cfg.BaseDN == "" || cfg.BindDN == "" || cfg.BindPassword == "" {
		return nil, errors.New("directory: baseDN, bindDN and a bind password are required")
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = DefaultUserFilter
	}
	if !strings.Contains(cfg.UserFilter, "{username}") {
		return nil, errors.New("directory: userFilter must contain {username}")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	return &LDAP{cfg: cfg, rootCAs: rootCAs}, nil
}

// tlsConfig returns the TLS configuration for a server.
func (d *LDAP) tlsConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		RootCAs:            d.rootCAs,
		InsecureSkipVerify: d.cfg.InsecureSkipVerify, //nolint:gosec // explicit opt-in for testing
		MinVersion:         tls.VersionTLS12,
	}
}

// dialURL opens an unauthenticated connection to one server.
func (d *LDAP) dialURL(rawURL string) (*ldap.Conn, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	tlsConfig := d.tlsConfig(parsed.Hostname())
	conn, err := ldap.DialURL(rawURL,
		ldap.DialWithDialer(&net.Dialer{Timeout: d.cfg.Timeout}),
		ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(d.cfg.Timeout)
	if d.cfg.StartTLS && parsed.Scheme == "ldap" {
		if err := conn.StartTLS(tlsConfig); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("starttls to %s: %w", rawURL, err)
		}
	}
	return conn, nil
}

// dial opens a connection to the first server that answers and says which one it was.
func (d *LDAP) dial(ctx context.Context) (*ldap.Conn, string, error) {
	var errs []error
	for _, rawURL := range d.cfg.URLs {
		conn, err := d.dialURL(rawURL)
		if err == nil {
			return conn, rawURL, nil
		}
		logutil.FromCtx(ctx).Warn("Domain controller unreachable", zap.String("url", rawURL), zap.Error(err))
		errs = append(errs, err)
	}
	return nil, "", fmt.Errorf("no domain controller reachable: %w", errors.Join(errs...))
}

// serviceConn opens a connection bound as the service account. If rawURL is empty the first
// reachable server is used.
func (d *LDAP) serviceConn(ctx context.Context, rawURL string) (*ldap.Conn, string, error) {
	var conn *ldap.Conn
	var err error
	if rawURL == "" {
		conn, rawURL, err = d.dial(ctx)
	} else {
		conn, err = d.dialURL(rawURL)
	}
	if err != nil {
		return nil, "", err
	}
	if err := conn.Bind(d.cfg.BindDN, d.cfg.BindPassword); err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("service account bind to %s: %w", rawURL, err)
	}
	return conn, rawURL, nil
}

// LookupUser implements Directory.
func (d *LDAP) LookupUser(ctx context.Context, username string) (*User, error) {
	username = NormaliseUsername(username)
	if username == "" {
		return nil, ErrUserNotFound
	}
	conn, _, err := d.serviceConn(ctx, "")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	filter := strings.ReplaceAll(d.cfg.UserFilter, "{username}", ldap.EscapeFilter(username))
	result, err := conn.Search(ldap.NewSearchRequest(d.cfg.BaseDN, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 2, int(d.cfg.Timeout.Seconds()), false, filter, userAttributes, nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("searching for user: %w", err)
	}
	if len(result.Entries) != 1 {
		return nil, ErrUserNotFound
	}
	return userFromEntry(result.Entries[0]), nil
}

// LookupDN implements Directory.
func (d *LDAP) LookupDN(ctx context.Context, dn string) (*User, error) {
	conn, _, err := d.serviceConn(ctx, "")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	result, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 1, int(d.cfg.Timeout.Seconds()), false, "(objectClass=user)", userAttributes, nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("reading user: %w", err)
	}
	if len(result.Entries) != 1 {
		return nil, ErrUserNotFound
	}
	return userFromEntry(result.Entries[0]), nil
}

// bindAs binds to rawURL as the user and classifies the result.
func (d *LDAP) bindAs(rawURL string, user *User, password []byte) (BindResult, error) {
	if len(password) == 0 {
		// An empty password is an unauthenticated bind, which always "succeeds".
		return BindInvalidCredentials, nil
	}
	conn, err := d.dialURL(rawURL)
	if err != nil {
		return BindFailed, err
	}
	defer conn.Close()
	return ClassifyBindError(conn.Bind(user.DN, string(password)))
}

// Authenticate implements Directory.
func (d *LDAP) Authenticate(ctx context.Context, user *User, password []byte) (BindResult, error) {
	var errs []error
	for _, rawURL := range d.cfg.URLs {
		result, err := d.bindAs(rawURL, user, password)
		if err == nil {
			return result, nil
		}
		logutil.FromCtx(ctx).Warn("Bind failed against domain controller", zap.String("url", rawURL), zap.Error(err))
		errs = append(errs, err)
	}
	return BindFailed, fmt.Errorf("no domain controller could check the password: %w", errors.Join(errs...))
}

// IsMemberOfAny implements Directory.
func (d *LDAP) IsMemberOfAny(ctx context.Context, user *User, groupDNs []string) (bool, error) {
	if len(groupDNs) == 0 {
		return false, nil
	}
	conn, _, err := d.serviceConn(ctx, "")
	if err != nil {
		return false, err
	}
	defer conn.Close()

	var filter strings.Builder
	filter.WriteString("(|")
	for _, groupDN := range groupDNs {
		fmt.Fprintf(&filter, "(memberOf:%s:=%s)", matchingRuleInChain, ldap.EscapeFilter(groupDN))
	}
	filter.WriteString(")")

	result, err := conn.Search(ldap.NewSearchRequest(user.DN, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 1, int(d.cfg.Timeout.Seconds()), false, filter.String(), []string{"1.1"}, nil))
	if err != nil {
		return false, fmt.Errorf("checking group membership: %w", err)
	}
	return len(result.Entries) > 0, nil
}

// clearLockout clears lockoutTime on the connection, which must be bound as the service account.
func clearLockout(conn *ldap.Conn, user *User) error {
	modify := ldap.NewModifyRequest(user.DN, nil)
	modify.Replace("lockoutTime", []string{"0"})
	if err := conn.Modify(modify); err != nil {
		return fmt.Errorf("clearing lockoutTime: %w", err)
	}
	return nil
}

// Unlock implements Directory.
func (d *LDAP) Unlock(ctx context.Context, user *User) error {
	conn, rawURL, err := d.serviceConn(ctx, "")
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := clearLockout(conn, user); err != nil {
		return err
	}
	logutil.FromCtx(ctx).Info("Cleared account lockout", zap.String("dn", user.DN), zap.String("url", rawURL))
	return nil
}

// isLockedOut reads msDS-User-Account-Control-Computed over conn and reports whether the
// account is currently locked.
func (d *LDAP) isLockedOut(conn *ldap.Conn, user *User) (bool, error) {
	result, err := conn.Search(ldap.NewSearchRequest(user.DN, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 1, int(d.cfg.Timeout.Seconds()), false, "(objectClass=*)",
		[]string{"msDS-User-Account-Control-Computed"}, nil))
	if err != nil {
		return false, fmt.Errorf("reading lockout state: %w", err)
	}
	if len(result.Entries) != 1 {
		return false, ErrUserNotFound
	}
	computed, err := strconv.ParseInt(result.Entries[0].GetAttributeValue("msDS-User-Account-Control-Computed"), 10, 64)
	if err != nil {
		return false, fmt.Errorf("parsing msDS-User-Account-Control-Computed: %w", err)
	}
	return computed&ufLockout != 0, nil
}

// domainDN returns the domain's distinguished name, i.e. the trailing DC= components of dn.
func domainDN(dn string) string {
	var parts []string
	for _, rdn := range strings.Split(dn, ",") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rdn)), "dc=") {
			parts = append(parts, strings.TrimSpace(rdn))
		}
	}
	return strings.Join(parts, ",")
}

// lockoutThreshold reads the account's effective lockout threshold: its fine-grained password
// policy (msDS-ResultantPSO) if it has one, otherwise the domain's lockoutThreshold. A zero
// threshold (lockout disabled) returns ErrLockoutNotConfigured.
func (d *LDAP) lockoutThreshold(conn *ldap.Conn, user *User) (int, error) {
	readInt := func(dn, attr string) (int64, bool, error) {
		result, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject,
			ldap.NeverDerefAliases, 1, int(d.cfg.Timeout.Seconds()), false, "(objectClass=*)",
			[]string{attr}, nil))
		if err != nil {
			return 0, false, err
		}
		if len(result.Entries) != 1 {
			return 0, false, nil
		}
		raw := result.Entries[0].GetAttributeValue(attr)
		if raw == "" {
			return 0, false, nil
		}
		value, err := strconv.ParseInt(raw, 10, 64)
		return value, err == nil, err
	}

	var threshold int64
	pso, _, err := readPSO(conn, user, d.cfg.Timeout)
	if err != nil {
		return 0, err
	}
	if pso != "" {
		value, ok, err := readInt(pso, "msDS-LockoutThreshold")
		if err != nil {
			return 0, fmt.Errorf("reading PSO lockout threshold: %w", err)
		}
		if !ok {
			// Falling back to the domain threshold here could leave the account short of its
			// real threshold, so refuse before anything is unlocked.
			return 0, fmt.Errorf("%w: %s", ErrPSOUnreadable, pso)
		}
		threshold = value
	}
	if threshold == 0 {
		domain := domainDN(user.DN)
		if domain == "" {
			domain = d.cfg.BaseDN
		}
		value, ok, err := readInt(domain, "lockoutThreshold")
		if err != nil {
			return 0, fmt.Errorf("reading domain lockout threshold: %w", err)
		}
		if ok {
			threshold = value
		}
	}
	if threshold <= 0 {
		return 0, ErrLockoutNotConfigured
	}
	return int(threshold), nil
}

// readPSO returns the DN of the account's resultant fine-grained password policy, or "" if it
// has none.
func readPSO(conn *ldap.Conn, user *User, timeout time.Duration) (string, bool, error) {
	result, err := conn.Search(ldap.NewSearchRequest(user.DN, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 1, int(timeout.Seconds()), false, "(objectClass=*)",
		[]string{"msDS-ResultantPSO"}, nil))
	if err != nil {
		return "", false, fmt.Errorf("reading msDS-ResultantPSO: %w", err)
	}
	if len(result.Entries) != 1 {
		return "", false, nil
	}
	pso := result.Entries[0].GetAttributeValue("msDS-ResultantPSO")
	return pso, pso != "", nil
}

// relock locks the account by binding with wrong passwords until it reaches its lockout
// threshold. The account must be unlocked when this is called. rawURL and threshold come from
// VerifyWhileLocked, which already read them against the same DC.
func (d *LDAP) relock(ctx context.Context, conn *ldap.Conn, rawURL string, user *User, threshold int) error {
	// A few extra attempts beyond the threshold cover a stray successful reset or an
	// observation-window edge, without risking a runaway loop.
	const extraAttempts = 5
	for attempt := 0; attempt < threshold+extraAttempts; attempt++ {
		if _, err := d.bindAs(rawURL, user, []byte(randomWrongPassword())); err != nil {
			return fmt.Errorf("re-lock bind: %w", err)
		}
		if attempt+1 < threshold {
			continue
		}
		locked, err := d.isLockedOut(conn, user)
		if err != nil {
			return err
		}
		if locked {
			logutil.FromCtx(ctx).Info("Re-locked account",
				zap.String("dn", user.DN), zap.Int("attempts", attempt+1))
			return nil
		}
	}
	return ErrRelockFailed
}

// randomWrongPassword returns a random string that won't match any real password. It's never
// empty, so each bind reaches the directory and counts towards lockout.
func randomWrongPassword() string {
	buf := make([]byte, 24)
	_, _ = rand.Read(buf) // crypto/rand.Read never returns an error
	return "!x" + hex.EncodeToString(buf)
}

// VerifyWhileLocked implements Directory.
func (d *LDAP) VerifyWhileLocked(ctx context.Context, user *User, password []byte, failsafeDescription string) (BindResult, error) {
	conn, rawURL, err := d.serviceConn(ctx, "")
	if err != nil {
		return BindFailed, err
	}
	defer conn.Close()

	// Read how many failed binds re-lock the account before unlocking it, so a directory
	// problem here can't leave the account unlocked.
	threshold, err := d.lockoutThreshold(conn, user)
	if err != nil {
		return BindFailed, fmt.Errorf("determining lockout threshold: %w", err)
	}

	if err := clearLockout(conn, user); err != nil {
		return BindFailed, err
	}
	logutil.FromCtx(ctx).Info("Temporarily cleared lockout to verify password",
		zap.String("dn", user.DN), zap.String("url", rawURL))

	result, verifyErr := d.bindAs(rawURL, user, password)

	if err := d.relock(ctx, conn, rawURL, user, threshold); err != nil {
		// The account is unlocked and we couldn't re-lock it. Disable it so a verified-but-
		// unconfirmed account can't be used, and make the failure loud.
		logutil.FromCtx(ctx).Error("Could not re-lock account after verification; disabling it",
			zap.String("dn", user.DN), zap.Error(err))
		derr := d.disableOnConn(conn, user, failsafeDescription)
		if errors.Is(derr, ErrDescriptionNotSet) {
			return BindFailed, fmt.Errorf("%w: account disabled as a safeguard (%w)", ErrRelockFailed, derr)
		}
		if derr != nil {
			return BindFailed, fmt.Errorf("%w; and disabling failed: %w", ErrRelockFailed, derr)
		}
		return BindFailed, fmt.Errorf("%w: account disabled as a safeguard", ErrRelockFailed)
	}

	if verifyErr != nil {
		return BindFailed, verifyErr
	}
	return result, nil
}

// Disable implements Directory.
func (d *LDAP) Disable(ctx context.Context, user *User, description string) error {
	conn, _, err := d.serviceConn(ctx, "")
	if err != nil {
		return err
	}
	defer conn.Close()
	return d.disableOnConn(conn, user, description)
}

// disableOnConn sets UF_ACCOUNTDISABLE, and the description if it's not empty, over the
// connection, which must be bound as the service account. Both change in one modify, so the
// account is never disabled without its explanation.
func (d *LDAP) disableOnConn(conn *ldap.Conn, user *User, description string) error {
	// Re-read userAccountControl so other flags changed since lookup aren't overwritten.
	result, err := conn.Search(ldap.NewSearchRequest(user.DN, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 1, int(d.cfg.Timeout.Seconds()), false, "(objectClass=*)",
		[]string{"userAccountControl"}, nil))
	if err != nil {
		return fmt.Errorf("reading userAccountControl: %w", err)
	}
	if len(result.Entries) != 1 {
		return ErrUserNotFound
	}
	uac, err := strconv.ParseInt(result.Entries[0].GetAttributeValue("userAccountControl"), 10, 64)
	if err != nil {
		return fmt.Errorf("parsing userAccountControl: %w", err)
	}

	disabled := strconv.FormatInt(uac|uacAccountDisable, 10)
	modify := ldap.NewModifyRequest(user.DN, nil)
	modify.Replace("userAccountControl", []string{disabled})
	if description = TruncateDescription(description); description != "" {
		modify.Replace("description", []string{description})
	}
	err = conn.Modify(modify)
	if err == nil {
		return nil
	}
	if description == "" || !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		return fmt.Errorf("disabling account: %w", err)
	}
	// The service account may lack write access to description. Disabling matters more than
	// explaining it, so disable without the description and report that it's missing.
	modify = ldap.NewModifyRequest(user.DN, nil)
	modify.Replace("userAccountControl", []string{disabled})
	if err := conn.Modify(modify); err != nil {
		return fmt.Errorf("disabling account: %w", err)
	}
	return fmt.Errorf("%w: %w", ErrDescriptionNotSet, err)
}
