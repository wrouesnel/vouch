// Samba generates its self-signed LDAPS certificate with a random serial number, which is
// sometimes negative. Go rejects those by default; real AD certificates don't have them.
//go:debug x509negativeserial=1

package directory_test

import (
	"context"
	"crypto/tls"
	"os"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/wrouesnel/vouch/pkg/audit"
	"github.com/wrouesnel/vouch/pkg/directory"
	"github.com/wrouesnel/vouch/pkg/unlock"
	"golang.org/x/text/encoding/unicode"
)

// These tests run against the Samba AD DC from test/samba. Start it with test/samba/start.sh
// and set VOUCH_SAMBA_URL=ldap://127.0.0.1:10389 to run them.

const (
	sambaBase      = "DC=vouch,DC=test"
	sambaUsers     = "CN=Users," + sambaBase
	sambaAdminDN   = "CN=Administrator," + sambaUsers
	sambaAdminPass = "Admin-Passw0rd!"
	sambaHelpdesk  = "CN=Helpdesk," + sambaUsers
	sambaProtected = "CN=Protected-Users-Vouch," + sambaUsers
	sambaThreshold = 3
	// sambaPSOThreshold is vouch-test-pso's threshold, applied to erin by setup.sh.
	sambaPSOThreshold = 5
	sambaWrongPass    = "definitely-wrong"
	sambaPassPrefix   = "Passw0rd-"
)

func sambaPassword(name string) string { return sambaPassPrefix + name + "!" }

func sambaURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("VOUCH_SAMBA_URL")
	if url == "" {
		t.Skip("VOUCH_SAMBA_URL not set; start test/samba/start.sh to run Samba integration tests")
	}
	return url
}

func sambaDirectory(t *testing.T) *directory.LDAP {
	t.Helper()
	dir, err := directory.NewLDAP(directory.Config{
		URLs:         []string{sambaURL(t)},
		BaseDN:       sambaBase,
		BindDN:       "CN=svc-vouch," + sambaUsers,
		BindPassword: sambaPassword("svc-vouch"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// sambaAdmin runs fn on a connection bound as Administrator.
func sambaAdmin(t *testing.T, fn func(conn *ldap.Conn)) {
	t.Helper()
	conn, err := ldap.DialURL(sambaURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind(sambaAdminDN, sambaAdminPass); err != nil {
		t.Fatal(err)
	}
	fn(conn)
}

// resetUser unlocks and enables a user, so tests leave the domain as they found it.
func resetUser(t *testing.T, name string) {
	t.Helper()
	sambaAdmin(t, func(conn *ldap.Conn) {
		modify := ldap.NewModifyRequest("CN="+name+","+sambaUsers, nil)
		modify.Replace("lockoutTime", []string{"0"})
		modify.Replace("userAccountControl", []string{"512"})
		modify.Replace("description", []string{})
		if err := conn.Modify(modify); err != nil {
			t.Fatalf("resetting %s: %v", name, err)
		}
	})
}

// lockOut locks a user by binding with a wrong password until AD locks the account.
func lockOut(t *testing.T, dir directory.Directory, user *directory.User) {
	t.Helper()
	lockOutAfter(t, dir, user, sambaThreshold)
}

// lockOutAfter locks a user whose lockout threshold is threshold.
func lockOutAfter(t *testing.T, dir directory.Directory, user *directory.User, threshold int) {
	t.Helper()
	ctx := context.Background()
	for range threshold {
		if _, err := dir.Authenticate(ctx, user, []byte(sambaWrongPass)); err != nil {
			t.Fatal(err)
		}
	}
	result, err := dir.Authenticate(ctx, user, []byte(sambaPassword(user.SAMAccountName)))
	if err != nil || result != directory.BindLockedOut {
		t.Fatalf("%s should be locked out: got %v, %v", user.SAMAccountName, result, err)
	}
}

func TestSambaDirectory(t *testing.T) {
	dir := sambaDirectory(t)
	ctx := context.Background()
	resetUser(t, "alice")
	resetUser(t, "carol")
	t.Cleanup(func() { resetUser(t, "alice"); resetUser(t, "carol") })

	alice, err := dir.LookupUser(ctx, `VOUCH\alice`)
	if err != nil {
		t.Fatal(err)
	}
	if byUPN, err := dir.LookupUser(ctx, "alice@vouch.test"); err != nil || !byUPN.SameAs(alice) {
		t.Fatalf("UPN lookup: %v", err)
	}
	if byDN, err := dir.LookupDN(ctx, alice.DN); err != nil || !byDN.SameAs(alice) {
		t.Fatalf("DN lookup: %v", err)
	}
	if _, err := dir.LookupUser(ctx, "nobody"); err != directory.ErrUserNotFound {
		t.Fatalf("unknown user: got %v", err)
	}
	if _, err := dir.LookupUser(ctx, "*"); err != directory.ErrUserNotFound {
		t.Fatalf("wildcard must be escaped and match nothing: got %v", err)
	}

	t.Run("bind results", func(t *testing.T) {
		result, err := dir.Authenticate(ctx, alice, []byte(sambaPassword("alice")))
		if err != nil || result != directory.BindOK {
			t.Fatalf("correct password: %v %v", result, err)
		}
		result, _ = dir.Authenticate(ctx, alice, nil)
		if result != directory.BindInvalidCredentials {
			t.Fatalf("empty password must not succeed: %v", result)
		}
	})

	t.Run("nested group membership", func(t *testing.T) {
		bob, err := dir.LookupUser(ctx, "bob")
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := dir.IsMemberOfAny(ctx, bob, []string{sambaHelpdesk}); err != nil || !ok {
			t.Fatalf("bob should be in Helpdesk through Helpdesk-L1: %v %v", ok, err)
		}
		if ok, err := dir.IsMemberOfAny(ctx, alice, []string{sambaHelpdesk, sambaProtected}); err != nil || ok {
			t.Fatalf("alice should not be in Helpdesk: %v %v", ok, err)
		}
	})

	t.Run("locked account does not reveal the password", func(t *testing.T) {
		lockOut(t, dir, alice)
		result, err := dir.Authenticate(ctx, alice, []byte(sambaWrongPass))
		if err != nil || result != directory.BindLockedOut {
			t.Fatalf("wrong password on a locked account: %v %v", result, err)
		}
	})

	t.Run("verify while locked re-locks the account", func(t *testing.T) {
		// Correct password: verified, and the account is locked again afterwards.
		result, err := dir.VerifyWhileLocked(ctx, alice, []byte(sambaPassword("alice")), "")
		if err != nil || result != directory.BindOK {
			t.Fatalf("verify with correct password: %v %v", result, err)
		}
		if r, _ := dir.Authenticate(ctx, alice, []byte(sambaPassword("alice"))); r != directory.BindLockedOut {
			t.Fatalf("account should be re-locked after verifying: %v", r)
		}

		// Wrong password: not verified, still locked.
		result, err = dir.VerifyWhileLocked(ctx, alice, []byte(sambaWrongPass), "")
		if err != nil || result != directory.BindInvalidCredentials {
			t.Fatalf("verify with wrong password: %v %v", result, err)
		}
		if r, _ := dir.Authenticate(ctx, alice, []byte(sambaPassword("alice"))); r != directory.BindLockedOut {
			t.Fatalf("account should still be locked: %v", r)
		}
	})

	t.Run("unlock clears the lockout", func(t *testing.T) {
		if err := dir.Unlock(ctx, alice); err != nil {
			t.Fatal(err)
		}
		if r, _ := dir.Authenticate(ctx, alice, []byte(sambaPassword("alice"))); r != directory.BindOK {
			t.Fatalf("account should be unlocked: %v", r)
		}
	})

	t.Run("disable", func(t *testing.T) {
		carol, err := dir.LookupUser(ctx, "carol")
		if err != nil {
			t.Fatal(err)
		}
		const description = "Disabled by vouch on 2026-01-01T00:00:00Z: integration test"
		if err := dir.Disable(ctx, carol, description); err != nil {
			t.Fatal(err)
		}
		if reread, err := dir.LookupDN(ctx, carol.DN); err != nil || reread.Description != description {
			t.Fatalf("description after disable: %q, %v", reread.Description, err)
		}
		result, err := dir.Authenticate(ctx, carol, []byte(sambaPassword("carol")))
		if err != nil || result != directory.BindDisabled {
			t.Fatalf("disabled account: %v %v", result, err)
		}
	})
}

// TestSambaWorkflow runs the whole unlock workflow against Samba.
func TestSambaWorkflow(t *testing.T) {
	dir := sambaDirectory(t)
	ctx := context.Background()
	resetUser(t, "alice")
	resetUser(t, "dadmin")
	t.Cleanup(func() { resetUser(t, "alice"); resetUser(t, "dadmin") })

	svc, err := unlock.NewService(dir, unlock.Policy{
		VoucherGroups:   []string{sambaHelpdesk},
		ProtectedGroups: []string{sambaProtected},
	}, audit.Nop{})
	if err != nil {
		t.Fatal(err)
	}
	client := unlock.Client{IP: "192.0.2.1", UserAgent: "test"}

	alice, err := dir.LookupUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	lockOut(t, dir, alice)

	if _, _, err := svc.StartVouch(ctx, client, "carol", sambaPassword("carol")); err == nil {
		t.Fatal("carol isn't in Helpdesk and must not be able to vouch")
	}
	state, sessionID, err := svc.StartVouch(ctx, client, "bob", sambaPassword("bob"))
	if err != nil || state.Stage != unlock.StageAwaitingClaim {
		t.Fatalf("voucher sign-in: %+v %v", state, err)
	}
	state, err = svc.Claim(ctx, sessionID, client, "alice", sambaPassword("alice"))
	if err != nil || state.Stage != unlock.StageAwaitingConfirmation {
		t.Fatalf("claim: %+v %v", state, err)
	}
	state, err = svc.Confirm(ctx, sessionID, client, "bob", sambaPassword("bob"), true)
	if err != nil || state.Outcome != unlock.OutcomeUnlocked {
		t.Fatalf("confirm: %+v %v", state, err)
	}
	if result, err := dir.Authenticate(ctx, alice, []byte(sambaPassword("alice"))); err != nil || result != directory.BindOK {
		t.Fatalf("alice should be able to sign in: %v %v", result, err)
	}

	t.Run("protected user is ineligible", func(t *testing.T) {
		dadmin, err := dir.LookupUser(ctx, "dadmin")
		if err != nil {
			t.Fatal(err)
		}
		lockOut(t, dir, dadmin)
		_, sessionID, err := svc.StartVouch(ctx, client, "bob", sambaPassword("bob"))
		if err != nil {
			t.Fatal(err)
		}
		state, err := svc.Claim(ctx, sessionID, client, "dadmin", sambaPassword("dadmin"))
		if err != nil || state.Outcome != unlock.OutcomeIneligible {
			t.Fatalf("claim for protected user: %+v %v", state, err)
		}
		if result, _ := dir.Authenticate(ctx, dadmin, []byte(sambaPassword("dadmin"))); result != directory.BindLockedOut {
			t.Fatalf("dadmin must stay locked: %v", result)
		}
	})
}

// TestSambaPasswordSettingsObject checks the lockout threshold is taken from a fine-grained
// password policy. setup.sh applies vouch-test-pso (threshold 5, above the domain's 3) to erin.
func TestSambaPasswordSettingsObject(t *testing.T) {
	dir := sambaDirectory(t)
	ctx := context.Background()
	resetUser(t, "erin")
	t.Cleanup(func() { resetUser(t, "erin") })

	erin, err := dir.LookupUser(ctx, "erin")
	if err != nil {
		t.Fatal(err)
	}
	lockOutAfter(t, dir, erin, sambaPSOThreshold)

	result, err := dir.VerifyWhileLocked(ctx, erin, []byte(sambaPassword("erin")), "")
	if err != nil || result != directory.BindOK {
		t.Fatalf("verify with correct password: %v %v", result, err)
	}
	if r, _ := dir.Authenticate(ctx, erin, []byte(sambaPassword("erin"))); r != directory.BindLockedOut {
		t.Fatalf("erin should be re-locked using the PSO's threshold: %v", r)
	}
	if reread, err := dir.LookupDN(ctx, erin.DN); err != nil || reread.Disabled() {
		t.Fatalf("erin must not have been disabled by the fail-safe: %v", err)
	}
}

// TestSambaServiceAccountIsLeastPrivilege checks svc-vouch can't change anything beyond the
// attributes it's been granted, using the same permission set as
// extras/Grant-VouchServiceAccount.ps1.
func TestSambaServiceAccountIsLeastPrivilege(t *testing.T) {
	url := sambaURL(t)
	conn, err := ldap.DialURL(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind("CN=svc-vouch,"+sambaUsers, sambaPassword("svc-vouch")); err != nil {
		t.Fatal(err)
	}

	denied := map[string]*ldap.ModifyRequest{}
	title := ldap.NewModifyRequest("CN=carol,"+sambaUsers, nil)
	title.Replace("title", []string{"Changed by svc-vouch"})
	denied["write another attribute"] = title
	member := ldap.NewModifyRequest(sambaHelpdesk, nil)
	member.Add("member", []string{"CN=svc-vouch," + sambaUsers})
	denied["join a voucher group"] = member
	pso := ldap.NewModifyRequest("CN=vouch-test-pso,CN=Password Settings Container,CN=System,"+sambaBase, nil)
	pso.Replace("msDS-LockoutThreshold", []string{"0"})
	denied["change a password policy"] = pso
	domain := ldap.NewModifyRequest(sambaBase, nil)
	domain.Replace("lockoutThreshold", []string{"0"})
	denied["change the domain lockout policy"] = domain

	for name, modify := range denied {
		if err := conn.Modify(modify); !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
			t.Errorf("%s: got %v, want insufficient access", name, err)
		}
	}

	// Password resets need the Reset Password extended right, which isn't granted. AD only
	// accepts unicodePwd over an encrypted connection, so use LDAPS.
	if err := resetPassword(t, sambaAdminDN, sambaAdminPass, "carol"); err != nil {
		t.Fatalf("Administrator should be able to reset a password, so the check below is meaningful: %v", err)
	}
	if err := resetPassword(t, "CN=svc-vouch,"+sambaUsers, sambaPassword("svc-vouch"), "carol"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		t.Errorf("reset a password: got %v, want insufficient access", err)
	}
}

// resetPassword sets name's password by replacing unicodePwd over LDAPS, bound as bindDN.
func resetPassword(t *testing.T, bindDN, bindPassword, name string) error {
	t.Helper()
	conn, err := ldap.DialURL(strings.Replace(strings.Replace(sambaURL(t), "ldap://", "ldaps://", 1), ":10389", ":10636", 1),
		ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})) //nolint:gosec // self-signed test DC
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatal(err)
	}
	encoded, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().String(`"` + sambaPassword(name) + `"`)
	if err != nil {
		t.Fatal(err)
	}
	modify := ldap.NewModifyRequest("CN="+name+","+sambaUsers, nil)
	modify.Replace("unicodePwd", []string{encoded})
	return conn.Modify(modify)
}
