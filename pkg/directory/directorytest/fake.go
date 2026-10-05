// Package directorytest provides an in-memory directory.Directory that behaves like Active
// Directory's lockout rules, for tests.
package directorytest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/wrouesnel/vouch/pkg/directory"
)

// FakeUser is a user in a Fake directory.
type FakeUser struct {
	User     directory.User
	Password string
	// Groups are the DNs of every group the user is in, including through nesting.
	Groups      []string
	Locked      bool
	BadPwdCount int
}

// Fake is an in-memory Directory. Like AD, a locked account rejects every bind as locked out
// whether or not the password is right, and LockoutThreshold wrong passwords lock it.
type Fake struct {
	mu               sync.Mutex
	users            map[string]*FakeUser
	LockoutThreshold int
	// Err, if set, is returned by every operation.
	Err error
	// RelockErr, if set, makes VerifyWhileLocked fail to re-lock (and so disable the account).
	RelockErr error
	// Unlocks counts calls to Unlock (the final, permanent unlock).
	Unlocks int
	// Verifications counts calls to VerifyWhileLocked.
	Verifications int
	// Binds counts bind attempts per sAMAccountName.
	Binds map[string]int
}

// NewFake returns an empty Fake with a lockout threshold of 3.
func NewFake() *Fake {
	return &Fake{users: map[string]*FakeUser{}, LockoutThreshold: 3, Binds: map[string]int{}}
}

// Add adds a user. Its DN defaults to CN=<name>,CN=Users,DC=example,DC=test.
func (f *Fake) Add(name, password string, groups ...string) *FakeUser {
	f.mu.Lock()
	defer f.mu.Unlock()
	user := &FakeUser{
		User: directory.User{
			DN:                 "CN=" + name + ",CN=Users,DC=example,DC=test",
			SAMAccountName:     name,
			UserPrincipalName:  name + "@example.test",
			DisplayName:        strings.ToUpper(name[:1]) + name[1:],
			ObjectSID:          []byte("sid-" + name),
			UserAccountControl: 512,
		},
		Password: password,
		Groups:   groups,
	}
	f.users[strings.ToLower(name)] = user
	return user
}

// Get returns a user by sAMAccountName.
func (f *Fake) Get(name string) *FakeUser {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.users[strings.ToLower(name)]
}

// Lock locks a user's account.
func (f *Fake) Lock(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	user := f.users[strings.ToLower(name)]
	user.Locked = true
	user.User.LockoutTime = time.Now()
}

func (f *Fake) find(username string) *FakeUser {
	username = strings.ToLower(directory.NormaliseUsername(username))
	if user, ok := f.users[username]; ok {
		return user
	}
	for _, user := range f.users {
		if strings.EqualFold(user.User.UserPrincipalName, username) {
			return user
		}
	}
	return nil
}

func (f *Fake) byDN(dn string) *FakeUser {
	for _, user := range f.users {
		if strings.EqualFold(user.User.DN, dn) {
			return user
		}
	}
	return nil
}

func snapshot(user *FakeUser) *directory.User {
	copied := user.User
	if !user.Locked {
		copied.LockoutTime = time.Time{}
	}
	return &copied
}

// LookupUser implements directory.Directory.
func (f *Fake) LookupUser(_ context.Context, username string) (*directory.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return nil, f.Err
	}
	user := f.find(username)
	if user == nil {
		return nil, directory.ErrUserNotFound
	}
	return snapshot(user), nil
}

// LookupDN implements directory.Directory.
func (f *Fake) LookupDN(_ context.Context, dn string) (*directory.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return nil, f.Err
	}
	user := f.byDN(dn)
	if user == nil {
		return nil, directory.ErrUserNotFound
	}
	return snapshot(user), nil
}

// bind applies AD's bind rules. mu must be held.
func (f *Fake) bind(dn string, password []byte) directory.BindResult {
	user := f.byDN(dn)
	if user == nil || len(password) == 0 {
		return directory.BindInvalidCredentials
	}
	f.Binds[user.User.SAMAccountName]++
	if user.Locked {
		return directory.BindLockedOut
	}
	if string(password) != user.Password {
		user.BadPwdCount++
		if f.LockoutThreshold > 0 && user.BadPwdCount >= f.LockoutThreshold {
			user.Locked = true
			user.User.LockoutTime = time.Now()
		}
		return directory.BindInvalidCredentials
	}
	if user.User.Disabled() {
		return directory.BindDisabled
	}
	user.BadPwdCount = 0
	return directory.BindOK
}

// Authenticate implements directory.Directory.
func (f *Fake) Authenticate(_ context.Context, user *directory.User, password []byte) (directory.BindResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return directory.BindFailed, f.Err
	}
	return f.bind(user.DN, password), nil
}

// IsMemberOfAny implements directory.Directory.
func (f *Fake) IsMemberOfAny(_ context.Context, user *directory.User, groupDNs []string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return false, f.Err
	}
	found := f.byDN(user.DN)
	if found == nil {
		return false, nil
	}
	for _, have := range found.Groups {
		for _, want := range groupDNs {
			if strings.EqualFold(have, want) {
				return true, nil
			}
		}
	}
	return false, nil
}

// UnlockAndVerify implements directory.Directory.
func (f *Fake) VerifyWhileLocked(_ context.Context, user *directory.User, password []byte) (directory.BindResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return directory.BindFailed, f.Err
	}
	if f.RelockErr != nil {
		// Mimic the real client: on a re-lock failure the account is disabled and locked state
		// is indeterminate, so treat it as disabled-and-locked here.
		found := f.byDN(user.DN)
		if found != nil {
			found.User.UserAccountControl |= 0x2
		}
		return directory.BindFailed, fmt.Errorf("%w: account disabled as a safeguard", directory.ErrRelockFailed)
	}
	found := f.byDN(user.DN)
	if found == nil {
		return directory.BindFailed, errors.New("no such object")
	}
	if f.LockoutThreshold <= 0 {
		return directory.BindFailed, directory.ErrLockoutNotConfigured
	}
	f.Verifications++
	// Unlock, check the password, then re-lock: the account is locked again on return.
	result := directory.BindInvalidCredentials
	if string(password) == found.Password && !found.User.Disabled() {
		result = directory.BindOK
	}
	found.Locked = true
	found.BadPwdCount = f.LockoutThreshold
	found.User.LockoutTime = time.Now()
	return result, nil
}

// Unlock implements directory.Directory.
func (f *Fake) Unlock(_ context.Context, user *directory.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return f.Err
	}
	found := f.byDN(user.DN)
	if found == nil {
		return directory.ErrUserNotFound
	}
	f.Unlocks++
	found.Locked = false
	found.BadPwdCount = 0
	found.User.LockoutTime = time.Time{}
	return nil
}

// Disable implements directory.Directory.
func (f *Fake) Disable(_ context.Context, user *directory.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return f.Err
	}
	found := f.byDN(user.DN)
	if found == nil {
		return directory.ErrUserNotFound
	}
	found.User.UserAccountControl |= 0x2
	return nil
}
