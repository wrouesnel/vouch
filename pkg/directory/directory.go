// Package directory talks to Active Directory over LDAP: it finds users, checks passwords by
// binding as them, resolves nested group membership and unlocks accounts.
package directory

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ErrUserNotFound is returned when a username doesn't match exactly one user.
var ErrUserNotFound = errors.New("user not found")

// BindResult classifies the outcome of binding as a user.
type BindResult int

const (
	// BindOK means the password was accepted.
	BindOK BindResult = iota
	// BindInvalidCredentials means the password was wrong, or the user doesn't exist.
	BindInvalidCredentials
	// BindLockedOut means the account is locked. AD doesn't say whether the password was right.
	BindLockedOut
	// BindDisabled means the account is disabled.
	BindDisabled
	// BindPasswordExpired means the password is right but has expired, or must be changed.
	BindPasswordExpired
	// BindAccountExpired means the account has expired.
	BindAccountExpired
	// BindRestricted means the account may not log on now or from here.
	BindRestricted
	// BindFailed is any other rejection.
	BindFailed
)

func (r BindResult) String() string {
	switch r {
	case BindOK:
		return "ok"
	case BindInvalidCredentials:
		return "invalid_credentials"
	case BindLockedOut:
		return "locked_out"
	case BindDisabled:
		return "disabled"
	case BindPasswordExpired:
		return "password_expired"
	case BindAccountExpired:
		return "account_expired"
	case BindRestricted:
		return "restricted"
	default:
		return "failed"
	}
}

// adDataCodePattern finds the Win32 sub-error AD puts in a bind failure's diagnostic message,
// e.g. "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 775, v4563".
var adDataCodePattern = regexp.MustCompile(`(?i)\bdata ([0-9a-f]{3,8})\b`)

// ClassifyBindError maps an error from an LDAP simple bind to a BindResult. Errors that aren't
// a directory rejection (network failures and the like) are returned unchanged.
func ClassifyBindError(err error) (BindResult, error) {
	if err == nil {
		return BindOK, nil
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != ldap.LDAPResultInvalidCredentials {
		return BindFailed, err
	}
	match := adDataCodePattern.FindStringSubmatch(ldapErr.Error())
	if match == nil {
		return BindInvalidCredentials, nil
	}
	switch strings.ToLower(match[1]) {
	case "525", "52e":
		return BindInvalidCredentials, nil
	case "775":
		return BindLockedOut, nil
	case "533":
		return BindDisabled, nil
	case "532", "773":
		return BindPasswordExpired, nil
	case "701":
		return BindAccountExpired, nil
	case "530", "531":
		return BindRestricted, nil
	default:
		return BindFailed, nil
	}
}

// userAccountControl flags. See MS-ADTS 2.2.16.
const (
	uacAccountDisable = 0x2
)

// User is a user object read from the directory.
type User struct {
	DN                 string
	SAMAccountName     string
	UserPrincipalName  string
	DisplayName        string
	Mail               string
	Title              string
	Department         string
	Description        string
	ObjectSID          []byte
	UserAccountControl int64
	// LockoutTime is when the account was locked, or the zero time if it isn't.
	LockoutTime time.Time
}

// Disabled reports whether the account is disabled.
func (u *User) Disabled() bool {
	return u.UserAccountControl&uacAccountDisable != 0
}

// SameAs reports whether u and other are the same directory object.
func (u *User) SameAs(other *User) bool {
	if len(u.ObjectSID) > 0 && len(other.ObjectSID) > 0 {
		return string(u.ObjectSID) == string(other.ObjectSID)
	}
	return strings.EqualFold(u.DN, other.DN)
}

// userAttributes are the attributes read for a User.
//
//nolint:gochecknoglobals
var userAttributes = []string{
	"sAMAccountName", "userPrincipalName", "displayName", "mail", "title", "department",
	"description", "objectSid", "userAccountControl", "lockoutTime",
}

// userFromEntry converts a search result into a User.
func userFromEntry(entry *ldap.Entry) *User {
	user := &User{
		DN:                entry.DN,
		SAMAccountName:    entry.GetAttributeValue("sAMAccountName"),
		UserPrincipalName: entry.GetAttributeValue("userPrincipalName"),
		DisplayName:       entry.GetAttributeValue("displayName"),
		Mail:              entry.GetAttributeValue("mail"),
		Title:             entry.GetAttributeValue("title"),
		Department:        entry.GetAttributeValue("department"),
		Description:       entry.GetAttributeValue("description"),
		ObjectSID:         entry.GetRawAttributeValue("objectSid"),
	}
	if uac, err := strconv.ParseInt(entry.GetAttributeValue("userAccountControl"), 10, 64); err == nil {
		user.UserAccountControl = uac
	}
	user.LockoutTime = fileTimeToTime(entry.GetAttributeValue("lockoutTime"))
	if user.DisplayName == "" {
		user.DisplayName = user.SAMAccountName
	}
	return user
}

// fileTimeToTime converts an AD FILETIME (100ns intervals since 1601-01-01 UTC) to a time.
// Zero, or a value that doesn't parse, gives the zero time.
func fileTimeToTime(value string) time.Time {
	fileTime, err := strconv.ParseInt(value, 10, 64)
	if err != nil || fileTime <= 0 {
		return time.Time{}
	}
	const epochDelta = 116444736000000000 // FILETIME of 1970-01-01
	return time.Unix(0, (fileTime-epochDelta)*100).UTC()
}

// NormaliseUsername strips a NetBIOS domain prefix (DOMAIN\user) and surrounding space.
// userPrincipalName forms (user@domain) are left alone.
func NormaliseUsername(username string) string {
	username = strings.TrimSpace(username)
	if idx := strings.LastIndex(username, `\`); idx >= 0 {
		username = username[idx+1:]
	}
	return username
}

// Directory is the set of directory operations vouch needs.
type Directory interface {
	// LookupUser finds a user by sAMAccountName or userPrincipalName. It returns
	// ErrUserNotFound if there isn't exactly one match.
	LookupUser(ctx context.Context, username string) (*User, error)
	// LookupDN reads a user by distinguished name. It returns ErrUserNotFound if there's no
	// such user.
	LookupDN(ctx context.Context, dn string) (*User, error)
	// Authenticate binds as the user to check the password.
	Authenticate(ctx context.Context, user *User, password []byte) (BindResult, error)
	// IsMemberOfAny reports whether the user is a member, directly or through nested groups,
	// of any of the groups.
	IsMemberOfAny(ctx context.Context, user *User, groupDNs []string) (bool, error)
	// UnlockAndVerify clears the account's lockout and then binds as the user to verify the
	// password, both against the same domain controller.
	UnlockAndVerify(ctx context.Context, user *User, password []byte) (BindResult, error)
	// Disable disables the account.
	Disable(ctx context.Context, user *User) error
}
