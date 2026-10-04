package directory_test

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/wrouesnel/vouch/pkg/directory"
)

func adError(data string) error {
	return &ldap.Error{
		ResultCode: ldap.LDAPResultInvalidCredentials,
		Err: errors.New("80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data " +
			data + ", v1db1"),
	}
}

func TestClassifyBindError(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		want    directory.BindResult
		wantErr bool
	}{
		{"ok", nil, directory.BindOK, false},
		{"wrong password", adError("52e"), directory.BindInvalidCredentials, false},
		{"no such user", adError("525"), directory.BindInvalidCredentials, false},
		{"locked", adError("775"), directory.BindLockedOut, false},
		{"disabled", adError("533"), directory.BindDisabled, false},
		{"password expired", adError("532"), directory.BindPasswordExpired, false},
		{"must change", adError("773"), directory.BindPasswordExpired, false},
		{"account expired", adError("701"), directory.BindAccountExpired, false},
		{"logon hours", adError("530"), directory.BindRestricted, false},
		{"unknown data", adError("999"), directory.BindFailed, false},
		{"no data code", &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("invalid")},
			directory.BindInvalidCredentials, false},
		{"other ldap error", &ldap.Error{ResultCode: ldap.LDAPResultUnavailable, Err: errors.New("busy")},
			directory.BindFailed, true},
		{"network error", errors.New("connection reset"), directory.BindFailed, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := directory.ClassifyBindError(tc.err)
			if got != tc.want {
				t.Errorf("result: got %v, want %v", got, tc.want)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("error: got %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

func TestNormaliseUsername(t *testing.T) {
	cases := map[string]string{
		"alice":              "alice",
		"  alice ":           "alice",
		`EXAMPLE\alice`:      "alice",
		"alice@example.test": "alice@example.test",
		`\`:                  "",
	}
	for in, want := range cases {
		if got := directory.NormaliseUsername(in); got != want {
			t.Errorf("NormaliseUsername(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewLDAPValidation(t *testing.T) {
	valid := directory.Config{
		URLs: []string{"ldaps://dc.example.test"}, BaseDN: "DC=example,DC=test",
		BindDN: "CN=svc,DC=example,DC=test", BindPassword: "secret",
	}
	if _, err := directory.NewLDAP(valid, nil); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	broken := []func(*directory.Config){
		func(c *directory.Config) { c.URLs = nil },
		func(c *directory.Config) { c.URLs = []string{"http://dc.example.test"} },
		func(c *directory.Config) { c.BindPassword = "" },
		func(c *directory.Config) { c.UserFilter = "(sAMAccountName=alice)" },
	}
	for idx, mutate := range broken {
		cfg := valid
		mutate(&cfg)
		if _, err := directory.NewLDAP(cfg, nil); err == nil {
			t.Errorf("case %d: invalid config accepted", idx)
		}
	}
}

func TestUserDisabledAndSameAs(t *testing.T) {
	alice := &directory.User{DN: "CN=alice,DC=x", ObjectSID: []byte{1, 2}, UserAccountControl: 514}
	if !alice.Disabled() {
		t.Error("UAC 514 should be disabled")
	}
	renamed := &directory.User{DN: "CN=alice2,DC=x", ObjectSID: []byte{1, 2}}
	if !alice.SameAs(renamed) {
		t.Error("same SID should be the same user")
	}
	if alice.SameAs(&directory.User{DN: "CN=alice,DC=x", ObjectSID: []byte{3}}) {
		t.Error("different SIDs should differ")
	}
	if !(&directory.User{DN: "CN=A,DC=x"}).SameAs(&directory.User{DN: "cn=a,dc=x"}) {
		t.Error("DNs should compare case-insensitively without SIDs")
	}
}
