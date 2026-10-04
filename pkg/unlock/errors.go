package unlock

import (
	"fmt"

	"github.com/wrouesnel/vouch/pkg/directory"
)

// Code identifies a class of failure. The values match the Problem codes in the API.
type Code string

// Failure codes.
const (
	CodeBadRequest           Code = "bad_request"
	CodeInvalidCredentials   Code = "invalid_credentials"
	CodeAccountRestricted    Code = "account_restricted"
	CodeRateLimited          Code = "rate_limited"
	CodeNoSession            Code = "no_session"
	CodeSessionExpired       Code = "session_expired"
	CodeWrongStage           Code = "wrong_stage"
	CodePresenceMismatch     Code = "presence_mismatch"
	CodeVoucherNotAuthorised Code = "voucher_not_authorised"
	CodeVoucherIsClaimant    Code = "voucher_is_claimant"
	CodeVoucherMismatch      Code = "voucher_mismatch"
	CodeAttestationRequired  Code = "attestation_required"
	CodeDirectoryError       Code = "directory_error"
)

// Error is a failure the user can be told about. Err, if set, is the underlying cause, which
// is logged but not shown.
type Error struct {
	Code    Code
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

func newError(code Code, message string) *Error {
	return &Error{Code: code, Message: message}
}

func directoryError(err error) *Error {
	return &Error{
		Code:    CodeDirectoryError,
		Message: "The directory couldn't be reached. Please try again shortly or contact the service desk.",
		Err:     err,
	}
}

func errInvalidCredentials() *Error {
	return newError(CodeInvalidCredentials, "The username or password is incorrect.")
}

func errNoSession() *Error {
	return newError(CodeNoSession, "There's no unlock in progress in this browser. Please start again.")
}

func errSessionExpired() *Error {
	return newError(CodeSessionExpired, "This unlock request has expired. Please start again.")
}

func errWrongStage() *Error {
	return newError(CodeWrongStage, "That step isn't available now. Please reload the page.")
}

func errPresenceMismatch() *Error {
	return newError(CodePresenceMismatch,
		"This unlock request was started in a different browser or network location, so it has been cancelled. "+
			"Both people must use the same browser on the same computer.")
}

func errVoucherMismatch(voucher *directory.User) *Error {
	return newError(CodeVoucherMismatch,
		"Sign in as "+voucher.SAMAccountName+", the colleague who started this request.")
}

func errRateLimited() *Error {
	return newError(CodeRateLimited, "Too many attempts. Please wait a while before trying again.")
}
