package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/labstack/echo/v5"
	"github.com/wrouesnel/vouch/pkg/api"
	"github.com/wrouesnel/vouch/pkg/audit"
	"github.com/wrouesnel/vouch/pkg/directory/directorytest"
	"github.com/wrouesnel/vouch/pkg/server"
	"github.com/wrouesnel/vouch/pkg/unlock"
)

const helpdesk = "CN=Helpdesk,DC=example,DC=test"

// browser sends requests to the server like one browser would, keeping its cookie.
type browser struct {
	t         *testing.T
	e         *echo.Echo
	cookie    *http.Cookie
	userAgent string
	remote    string
}

func newServer(t *testing.T) (*echo.Echo, *directorytest.Fake) {
	t.Helper()
	dir := directorytest.NewFake()
	dir.Add("alice", "alice-password")
	dir.Add("bob", "bob-password", helpdesk)
	dir.Lock("alice")
	svc, err := unlock.NewService(dir, unlock.Policy{VoucherGroups: []string{helpdesk}}, audit.Nop{})
	if err != nil {
		t.Fatal(err)
	}
	web := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<!doctype html><title>test</title>")}}
	e, err := server.New(context.Background(), server.Config{}, svc, web)
	if err != nil {
		t.Fatal(err)
	}
	return e, dir
}

func newBrowser(t *testing.T, e *echo.Echo) *browser {
	return &browser{t: t, e: e, userAgent: "TestBrowser/1.0", remote: "192.0.2.10:5000"}
}

func (b *browser) do(method, path string, body any, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	b.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			b.t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Host = "vouch.example.test"
	req.RemoteAddr = b.remote
	req.Header.Set("User-Agent", b.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.cookie != nil {
		req.AddCookie(b.cookie)
	}
	for _, fn := range mutate {
		fn(req)
	}
	rec := httptest.NewRecorder()
	b.e.ServeHTTP(rec, req)
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == server.SessionCookie {
			if cookie.MaxAge < 0 {
				b.cookie = nil
			} else {
				b.cookie = cookie
			}
		}
	}
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(rec.Body.Bytes(), &value); err != nil {
		t.Fatalf("decoding %q: %v", rec.Body.String(), err)
	}
	return value
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status: got %d, want %d: %s", rec.Code, status, rec.Body.String())
	}
}

func TestFullFlow(t *testing.T) {
	e, dir := newServer(t)
	b := newBrowser(t, e)

	rec := b.do(http.MethodGet, "/api/v1/session", nil)
	wantStatus(t, rec, http.StatusOK)
	if state := decode[api.SessionState](t, rec); state.Stage != api.Start {
		t.Fatalf("initial stage: %s", state.Stage)
	}

	rec = b.do(http.MethodPost, "/api/v1/session/voucher", api.Credentials{Username: "bob", Password: "bob-password"})
	wantStatus(t, rec, http.StatusOK)
	if state := decode[api.SessionState](t, rec); state.Stage != api.AwaitingClaim || state.Voucher == nil {
		t.Fatalf("after voucher sign-in: %+v", state)
	}
	if b.cookie == nil {
		t.Fatal("no session cookie set")
	}
	if !b.cookie.HttpOnly || !b.cookie.Secure || b.cookie.SameSite != http.SameSiteStrictMode || b.cookie.Path != "/api/v1" {
		t.Fatalf("session cookie flags: %+v", b.cookie)
	}

	rec = b.do(http.MethodPost, "/api/v1/session/claim", api.Credentials{Username: "alice", Password: "alice-password"})
	wantStatus(t, rec, http.StatusOK)
	state := decode[api.SessionState](t, rec)
	if state.Stage != api.AwaitingConfirmation || state.Target == nil || state.Target.Username != "alice" {
		t.Fatalf("after claim: %+v", state)
	}

	rec = b.do(http.MethodPost, "/api/v1/session/confirm",
		api.Confirmation{Username: "bob", Password: "bob-password", Attest: true})
	wantStatus(t, rec, http.StatusOK)
	state = decode[api.SessionState](t, rec)
	if state.Outcome == nil || *state.Outcome != api.Unlocked {
		t.Fatalf("after confirm: %+v", state)
	}
	if dir.Get("alice").Locked {
		t.Fatal("alice should be unlocked")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("API responses must not be cached")
	}

	wantStatus(t, b.do(http.MethodDelete, "/api/v1/session", nil), http.StatusNoContent)
	if b.cookie != nil {
		t.Fatal("cancel should clear the cookie")
	}
}

func TestOtherBrowserCannotClaim(t *testing.T) {
	e, _ := newServer(t)
	voucher := newBrowser(t, e)
	wantStatus(t, voucher.do(http.MethodPost, "/api/v1/session/voucher",
		api.Credentials{Username: "bob", Password: "bob-password"}), http.StatusOK)

	// Without the cookie there is no session.
	other := newBrowser(t, e)
	rec := other.do(http.MethodPost, "/api/v1/session/claim", api.Credentials{Username: "alice", Password: "alice-password"})
	wantStatus(t, rec, http.StatusConflict)
	if problem := decode[api.Problem](t, rec); problem.Code != api.NoSession {
		t.Fatalf("problem: %+v", problem)
	}

	// With a stolen cookie but from another machine, the session is cancelled.
	other.cookie = voucher.cookie
	other.remote = "198.51.100.7:4000"
	rec = other.do(http.MethodPost, "/api/v1/session/claim", api.Credentials{Username: "alice", Password: "alice-password"})
	wantStatus(t, rec, http.StatusForbidden)
	if problem := decode[api.Problem](t, rec); problem.Code != api.PresenceMismatch {
		t.Fatalf("problem: %+v", problem)
	}
	rec = voucher.do(http.MethodGet, "/api/v1/session", nil)
	if state := decode[api.SessionState](t, rec); state.Stage != api.Start {
		t.Fatalf("session should be gone: %+v", state)
	}
}

func TestCrossSiteRequestsRejected(t *testing.T) {
	e, _ := newServer(t)
	b := newBrowser(t, e)
	creds := api.Credentials{Username: "bob", Password: "bob-password"}

	rec := b.do(http.MethodPost, "/api/v1/session/voucher", creds, func(r *http.Request) {
		r.Header.Set("Origin", "https://evil.example")
	})
	wantStatus(t, rec, http.StatusForbidden)

	rec = b.do(http.MethodPost, "/api/v1/session/voucher", creds, func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	})
	wantStatus(t, rec, http.StatusForbidden)

	rec = b.do(http.MethodPost, "/api/v1/session/voucher", creds, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	wantStatus(t, rec, http.StatusUnsupportedMediaType)

	rec = b.do(http.MethodPost, "/api/v1/session/voucher", creds, func(r *http.Request) {
		r.Header.Set("Origin", "https://vouch.example.test")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	})
	wantStatus(t, rec, http.StatusOK)
}

func TestErrorsAreProblems(t *testing.T) {
	e, _ := newServer(t)
	b := newBrowser(t, e)

	rec := b.do(http.MethodPost, "/api/v1/session/claim", api.Credentials{Username: "alice", Password: "nope"})
	wantStatus(t, rec, http.StatusConflict) // no voucher has signed in

	rec = b.do(http.MethodPost, "/api/v1/session/voucher", api.Credentials{Username: "bob", Password: "nope"})
	wantStatus(t, rec, http.StatusUnauthorized)
	if problem := decode[api.Problem](t, rec); problem.Code != api.InvalidCredentials {
		t.Fatalf("problem: %+v", problem)
	}

	rec = b.do(http.MethodGet, "/api/v1/nothing-here", nil)
	wantStatus(t, rec, http.StatusNotFound)
	if problem := decode[api.Problem](t, rec); problem.Code == "" {
		t.Fatal("unknown API paths should return a Problem")
	}

	rec = b.do(http.MethodPost, "/api/v1/session/voucher", nil, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		r.Body = http.NoBody
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body: got %d", rec.Code)
	}
}

func TestServesWebInterface(t *testing.T) {
	e, _ := newServer(t)
	b := newBrowser(t, e)
	for _, path := range []string{"/", "/some/client/route"} {
		rec := b.do(http.MethodGet, path, nil)
		wantStatus(t, rec, http.StatusOK)
		if !strings.Contains(rec.Body.String(), "<title>test</title>") {
			t.Fatalf("%s: got %q", path, rec.Body.String())
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatalf("%s: CSP %q", path, csp)
		}
	}
}

func TestInfo(t *testing.T) {
	e, _ := newServer(t)
	rec := newBrowser(t, e).do(http.MethodGet, "/api/v1/info", nil)
	wantStatus(t, rec, http.StatusOK)
	info := decode[api.Info](t, rec)
	if info.SessionLifetimeSeconds != int(unlock.DefaultSessionLifetime.Seconds()) || info.Title == "" {
		t.Fatalf("info: %+v", info)
	}
}
