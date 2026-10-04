package directory_test

import (
	"context"
	"os"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/wrouesnel/vouch/pkg/directory"
	"github.com/wrouesnel/vouch/pkg/unlock"
)

// These tests run against the Samba AD DC from test/samba. Start it with test/samba/start.sh
// and set VOUCH_SAMBA_URL=ldap://127.0.0.1:10389 to run them.

const (
	sambaBase       = "DC=vouch,DC=test"
	sambaUsers      = "CN=Users," + sambaBase
	sambaAdminDN    = "CN=Administrator," + sambaUsers
	sambaAdminPass  = "Admin-Passw0rd!"
	sambaHelpdesk   = "CN=Helpdesk," + sambaUsers
	sambaProtected  = "CN=Protected-Users-Vouch," + sambaUsers
	sambaThreshold  = 3
	sambaWrongPass  = "definitely-wrong"
	sambaPassPrefix = "Passw0rd-"
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
		if err := conn.Modify(modify); err != nil {
			t.Fatalf("resetting %s: %v", name, err)
		}
	})
}

// lockOut locks a user by binding with a wrong password until AD locks the account.
func lockOut(t *testing.T, dir directory.Directory, user *directory.User) {
	t.Helper()
	ctx := context.Background()
	for range sambaThreshold {
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

	t.Run("unlock and verify", func(t *testing.T) {
		result, err := dir.UnlockAndVerify(ctx, alice, []byte(sambaPassword("alice")))
		if err != nil || result != directory.BindOK {
			t.Fatalf("unlock with correct password: %v %v", result, err)
		}
		lockOut(t, dir, alice)
		result, err = dir.UnlockAndVerify(ctx, alice, []byte(sambaWrongPass))
		if err != nil || result != directory.BindInvalidCredentials {
			t.Fatalf("unlock with wrong password: %v %v", result, err)
		}
	})

	t.Run("disable", func(t *testing.T) {
		carol, err := dir.LookupUser(ctx, "carol")
		if err != nil {
			t.Fatal(err)
		}
		if err := dir.Disable(ctx, carol); err != nil {
			t.Fatal(err)
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
	})
	if err != nil {
		t.Fatal(err)
	}
	client := unlock.Client{IP: "192.0.2.1", UserAgent: "test"}

	alice, err := dir.LookupUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	lockOut(t, dir, alice)

	state, sessionID, err := svc.Claim(ctx, client, "alice", sambaPassword("alice"))
	if err != nil || state.Stage != unlock.StageAwaitingVoucher {
		t.Fatalf("claim: %+v %v", state, err)
	}
	if _, err := svc.Vouch(ctx, sessionID, client, "carol", sambaPassword("carol")); err == nil {
		t.Fatal("carol isn't in Helpdesk and must not be able to vouch")
	}
	state, err = svc.Vouch(ctx, sessionID, client, "bob", sambaPassword("bob"))
	if err != nil || state.Stage != unlock.StageAwaitingConfirmation {
		t.Fatalf("vouch: %+v %v", state, err)
	}
	state, err = svc.Confirm(ctx, sessionID, client, true)
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
		_, sessionID, err := svc.Claim(ctx, client, "dadmin", sambaPassword("dadmin"))
		if err != nil {
			t.Fatal(err)
		}
		state, err := svc.Vouch(ctx, sessionID, client, "bob", sambaPassword("bob"))
		if err != nil || state.Outcome != unlock.OutcomeIneligible {
			t.Fatalf("vouch for protected user: %+v %v", state, err)
		}
		if result, _ := dir.Authenticate(ctx, dadmin, []byte(sambaPassword("dadmin"))); result != directory.BindLockedOut {
			t.Fatalf("dadmin must stay locked: %v", result)
		}
	})
}
