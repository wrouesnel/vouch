// Package server serves the vouch API and web interface with Echo.
package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	logutil "github.com/wrouesnel/go.logutil"
	"github.com/wrouesnel/vouch/pkg/api"
	"github.com/wrouesnel/vouch/pkg/directory"
	"github.com/wrouesnel/vouch/pkg/unlock"
	"go.uber.org/zap"
)

// SessionCookie holds the session ID.
const SessionCookie = "vouch_session"

// apiBase is where the API is mounted.
const apiBase = "/api/v1"

// maxBodyBytes caps API request bodies.
const maxBodyBytes = 16 * 1024

// contentSecurityPolicy only allows the page's own scripts and styles.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// Config configures the web server.
type Config struct {
	// Listen is the address to listen on.
	Listen string `yaml:"listen"`
	// TLSCertFile and TLSKeyFile enable HTTPS. Without them, put vouch behind a TLS proxy.
	TLSCertFile string `yaml:"tlsCertFile"`
	TLSKeyFile  string `yaml:"tlsKeyFile"`
	// InsecureCookies drops the Secure flag from the session cookie. Browsers accept Secure
	// cookies from http://localhost, so this is only needed for plain HTTP on other hosts.
	InsecureCookies bool `yaml:"insecureCookies"`
	// TrustedProxies are CIDRs of reverse proxies whose X-Forwarded-For header is believed.
	// Without them the TCP peer is the client address.
	TrustedProxies []string `yaml:"trustedProxies"`
	// Title is shown at the top of the page.
	Title string `yaml:"title"`
	// VoucherDescription tells users who can vouch for them.
	VoucherDescription string `yaml:"voucherDescription"`
	// HelpText is optional extra guidance shown when the locked-out user enters their details.
	HelpText string `yaml:"helpText"`
}

// Handler implements api.ServerInterface.
type Handler struct {
	cfg Config
	svc *unlock.Service
}

var _ api.ServerInterface = (*Handler)(nil)

// New builds the Echo server. web holds the built web interface.
func New(ctx context.Context, cfg Config, svc *unlock.Service, web fs.FS) (*echo.Echo, error) {
	if cfg.Title == "" {
		cfg.Title = "Account unlock"
	}
	if cfg.VoucherDescription == "" {
		cfg.VoucherDescription = "an authorised colleague"
	}

	e := echo.New()
	e.HTTPErrorHandler = errorHandler

	extractor, err := ipExtractor(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	e.IPExtractor = extractor

	logger := logutil.FromCtx(ctx).Named("http")
	e.Use(middleware.Recover())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus: true, LogURIPath: true, LogMethod: true, LogRemoteIP: true, LogLatency: true,
		HandleError: true,
		LogValuesFunc: func(_ *echo.Context, v middleware.RequestLoggerValues) error {
			logger.Debug("Request", zap.String("method", v.Method), zap.String("path", v.URIPath),
				zap.Int("status", v.Status), zap.String("remote_ip", v.RemoteIP),
				zap.Duration("latency", v.Latency))
			return nil
		},
	}))
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "0",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		HSTSMaxAge:            hstsMaxAge(cfg),
		ContentSecurityPolicy: contentSecurityPolicy,
		ReferrerPolicy:        "no-referrer",
	}))

	handler := &Handler{cfg: cfg, svc: svc}
	group := e.Group(apiBase, noStore, sameOrigin, middleware.BodyLimit(maxBodyBytes))
	api.RegisterHandlers(group, handler)
	// Unmatched API paths must not fall through to the web interface.
	group.Any("/*", func(_ *echo.Context) error { return echo.ErrNotFound })

	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Skipper:    func(c *echo.Context) bool { return strings.HasPrefix(c.Request().URL.Path, "/api/") },
		Filesystem: web,
		Root:       ".",
		Index:      "index.html",
		HTML5:      true,
	}))
	return e, nil
}

// hstsMaxAge enables HSTS only when vouch serves TLS itself.
func hstsMaxAge(cfg Config) int {
	if cfg.TLSCertFile != "" {
		return int((365 * 24 * time.Hour).Seconds())
	}
	return 0
}

// ipExtractor picks how the client address is found.
func ipExtractor(trustedProxies []string) (echo.IPExtractor, error) {
	if len(trustedProxies) == 0 {
		return echo.ExtractIPDirect(), nil
	}
	options := []echo.TrustOption{
		echo.TrustLoopback(false), echo.TrustLinkLocal(false), echo.TrustPrivateNet(false),
	}
	for _, cidr := range trustedProxies {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("trustedProxies: %w", err)
		}
		options = append(options, echo.TrustIPRange(ipNet))
	}
	return echo.ExtractIPFromXFFHeader(options...), nil
}

// noStore stops API responses being cached.
func noStore(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		return next(c)
	}
}

// sameOrigin rejects state-changing requests that didn't come from this site's own pages.
// Together with the SameSite=Strict cookie and the JSON-only bodies, this stops other sites
// driving the workflow through a user's browser.
func sameOrigin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		req := c.Request()
		if req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == http.MethodOptions {
			return next(c)
		}
		if site := req.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			return problem(c, http.StatusForbidden, api.BadRequest, "Cross-site requests are not allowed.")
		}
		if origin := req.Header.Get("Origin"); origin != "" {
			parsed, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(parsed.Host, req.Host) {
				return problem(c, http.StatusForbidden, api.BadRequest, "Cross-origin requests are not allowed.")
			}
		}
		if req.Method == http.MethodPost {
			mediaType := strings.TrimSpace(strings.Split(req.Header.Get("Content-Type"), ";")[0])
			if !strings.EqualFold(mediaType, "application/json") {
				return problem(c, http.StatusUnsupportedMediaType, api.BadRequest, "Requests must be JSON.")
			}
		}
		return next(c)
	}
}

func problem(c *echo.Context, status int, code api.ProblemCode, message string) error {
	return c.JSON(status, api.Problem{Code: code, Message: message})
}

// errorHandler reports Echo's own errors (no route, body too large and so on) as Problems.
func errorHandler(c *echo.Context, err error) {
	if r, _ := echo.UnwrapResponse(c.Response()); r != nil && r.Committed {
		return
	}
	status := http.StatusInternalServerError
	var coder echo.HTTPStatusCoder
	if errors.As(err, &coder) && coder.StatusCode() != 0 {
		status = coder.StatusCode()
	}
	_ = problem(c, status, api.BadRequest, http.StatusText(status))
}

// unlockStatus maps a workflow failure to an HTTP status.
//
//nolint:gochecknoglobals
var unlockStatus = map[unlock.Code]int{
	unlock.CodeBadRequest:           http.StatusBadRequest,
	unlock.CodeInvalidCredentials:   http.StatusUnauthorized,
	unlock.CodeAccountRestricted:    http.StatusForbidden,
	unlock.CodeRateLimited:          http.StatusTooManyRequests,
	unlock.CodeNoSession:            http.StatusConflict,
	unlock.CodeSessionExpired:       http.StatusConflict,
	unlock.CodeWrongStage:           http.StatusConflict,
	unlock.CodePresenceMismatch:     http.StatusForbidden,
	unlock.CodeVoucherNotAuthorised: http.StatusForbidden,
	unlock.CodeVoucherIsClaimant:    http.StatusForbidden,
	unlock.CodeVoucherMismatch:      http.StatusForbidden,
	unlock.CodeAttestationRequired:  http.StatusBadRequest,
	unlock.CodeDirectoryError:       http.StatusBadGateway,
}

// failure reports a workflow error.
func (h *Handler) failure(c *echo.Context, err error) error {
	var unlockErr *unlock.Error
	if !errors.As(err, &unlockErr) {
		logutil.FromCtx(c.Request().Context()).Error("Unexpected error", zap.Error(err))
		return problem(c, http.StatusInternalServerError, api.DirectoryError, "Something went wrong.")
	}
	status, ok := unlockStatus[unlockErr.Code]
	if !ok {
		status = http.StatusInternalServerError
	}
	if unlockErr.Code == unlock.CodePresenceMismatch || unlockErr.Code == unlock.CodeNoSession ||
		unlockErr.Code == unlock.CodeSessionExpired && h.sessionGone(c) {
		h.clearSession(c)
	}
	return problem(c, status, api.ProblemCode(unlockErr.Code), unlockErr.Message)
}

// sessionGone reports whether this browser's session no longer exists.
func (h *Handler) sessionGone(c *echo.Context) bool {
	state, err := h.svc.State(c.Request().Context(), h.sessionID(c), h.client(c))
	return err != nil || state.Stage == unlock.StageStart
}

func (h *Handler) client(c *echo.Context) unlock.Client {
	return unlock.Client{IP: c.RealIP(), UserAgent: c.Request().UserAgent()}
}

func (h *Handler) sessionID(c *echo.Context) string {
	cookie, err := c.Cookie(SessionCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (h *Handler) setSession(c *echo.Context, sessionID string, expires time.Time) {
	c.SetCookie(&http.Cookie{
		Name:     SessionCookie,
		Value:    sessionID,
		Path:     apiBase,
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()) + 1,
		Secure:   !h.cfg.InsecureCookies,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) clearSession(c *echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     apiBase,
		MaxAge:   -1,
		Secure:   !h.cfg.InsecureCookies,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func toAccount(user *directory.User) *api.Account {
	if user == nil {
		return nil
	}
	optional := func(value string) *string {
		if value == "" {
			return nil
		}
		return &value
	}
	return &api.Account{
		Username:    user.SAMAccountName,
		DisplayName: user.DisplayName,
		Mail:        optional(user.Mail),
		Title:       optional(user.Title),
		Department:  optional(user.Department),
		Description: optional(user.Description),
	}
}

func toSessionState(state unlock.State) api.SessionState {
	result := api.SessionState{
		Stage:   api.Stage(state.Stage),
		Target:  toAccount(state.Target),
		Voucher: toAccount(state.Voucher),
	}
	if state.ClaimedUsername != "" {
		result.ClaimedUsername = &state.ClaimedUsername
	}
	if state.Outcome != unlock.OutcomeNone {
		outcome := api.Outcome(state.Outcome)
		result.Outcome = &outcome
	}
	if state.Message != "" {
		result.Message = &state.Message
	}
	if !state.ExpiresAt.IsZero() {
		result.ExpiresAt = &state.ExpiresAt
	}
	if !state.ConfirmBy.IsZero() {
		result.ConfirmBy = &state.ConfirmBy
	}
	return result
}

// GetInfo implements api.ServerInterface.
func (h *Handler) GetInfo(c *echo.Context) error {
	policy := h.svc.Policy()
	info := api.Info{
		Title:                  h.cfg.Title,
		VoucherDescription:     h.cfg.VoucherDescription,
		SessionLifetimeSeconds: int(policy.SessionLifetime.Seconds()),
		ConfirmWindowSeconds:   int(policy.ConfirmWindow.Seconds()),
	}
	if h.cfg.HelpText != "" {
		info.HelpText = &h.cfg.HelpText
	}
	return c.JSON(http.StatusOK, info)
}

// GetSession implements api.ServerInterface.
func (h *Handler) GetSession(c *echo.Context) error {
	state, err := h.svc.State(c.Request().Context(), h.sessionID(c), h.client(c))
	if err != nil {
		return h.failure(c, err)
	}
	if state.Stage == unlock.StageStart && h.sessionID(c) != "" {
		h.clearSession(c)
	}
	return c.JSON(http.StatusOK, toSessionState(state))
}

// CancelSession implements api.ServerInterface.
func (h *Handler) CancelSession(c *echo.Context) error {
	h.svc.Cancel(c.Request().Context(), h.sessionID(c))
	h.clearSession(c)
	return c.NoContent(http.StatusNoContent)
}

// badBody reports a request body that couldn't be decoded.
func badBody(c *echo.Context) error {
	return problem(c, http.StatusBadRequest, api.BadRequest, "The request couldn't be read.")
}

// SubmitVoucher implements api.ServerInterface.
func (h *Handler) SubmitVoucher(c *echo.Context) error {
	var body api.Credentials
	if err := c.Bind(&body); err != nil {
		return badBody(c)
	}
	ctx := c.Request().Context()
	// A voucher signing in replaces whatever this browser was doing before.
	if oldID := h.sessionID(c); oldID != "" {
		h.svc.Cancel(ctx, oldID)
		h.clearSession(c)
	}
	state, sessionID, err := h.svc.StartVouch(ctx, h.client(c), body.Username, body.Password)
	if err != nil {
		return h.failure(c, err)
	}
	h.setSession(c, sessionID, state.ExpiresAt)
	return c.JSON(http.StatusOK, toSessionState(state))
}

// SubmitClaim implements api.ServerInterface.
func (h *Handler) SubmitClaim(c *echo.Context) error {
	var body api.Credentials
	if err := c.Bind(&body); err != nil {
		return badBody(c)
	}
	state, err := h.svc.Claim(c.Request().Context(), h.sessionID(c), h.client(c), body.Username, body.Password)
	if err != nil {
		return h.failure(c, err)
	}
	return c.JSON(http.StatusOK, toSessionState(state))
}

// ConfirmVouch implements api.ServerInterface.
func (h *Handler) ConfirmVouch(c *echo.Context) error {
	var body api.Confirmation
	if err := c.Bind(&body); err != nil {
		return badBody(c)
	}
	state, err := h.svc.Confirm(c.Request().Context(), h.sessionID(c), h.client(c),
		body.Username, body.Password, body.Attest)
	if err != nil {
		return h.failure(c, err)
	}
	return c.JSON(http.StatusOK, toSessionState(state))
}
