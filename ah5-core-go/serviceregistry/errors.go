package main

import (
	"encoding/json"
	"net/http"
)

// ExType mirrors eu.arrowhead.dto.enums.ExceptionType.
type ExType string

const (
	ExArrowhead      ExType = "ARROWHEAD"
	ExInvalidParam   ExType = "INVALID_PARAMETER"
	ExAuth           ExType = "AUTH"
	ExForbidden      ExType = "FORBIDDEN"
	ExDataNotFound   ExType = "DATA_NOT_FOUND"
	ExTimeout        ExType = "TIMEOUT"
	ExLocked         ExType = "LOCKED"
	ExInternal       ExType = "INTERNAL_SERVER_ERROR"
	ExExternalServer ExType = "EXTERNAL_SERVER_ERROR"
)

func (t ExType) status() int {
	switch t {
	case ExInvalidParam:
		return http.StatusBadRequest
	case ExAuth:
		return http.StatusUnauthorized
	case ExForbidden:
		return http.StatusForbidden
	case ExDataNotFound:
		return http.StatusNotFound
	case ExTimeout:
		return http.StatusRequestTimeout
	case ExLocked:
		return 423
	case ExExternalServer:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// AHError is the Go counterpart of ArrowheadException and its subclasses.
type AHError struct {
	Type   ExType
	Msg    string
	Origin string
}

func (e *AHError) Error() string { return e.Msg }

func errInvalid(msg string) *AHError   { return &AHError{Type: ExInvalidParam, Msg: msg} }
func errAuth(msg string) *AHError      { return &AHError{Type: ExAuth, Msg: msg} }
func errForbidden(msg string) *AHError { return &AHError{Type: ExForbidden, Msg: msg} }
func errLocked(msg string) *AHError    { return &AHError{Type: ExLocked, Msg: msg} }
func errInternal(msg string) *AHError  { return &AHError{Type: ExInternal, Msg: msg} }

// withOrigin sets the origin on an error if it has none yet.
func withOrigin(err error, origin string) error {
	if err == nil {
		return nil
	}
	if ae, ok := err.(*AHError); ok {
		if ae.Origin == "" {
			cp := *ae
			cp.Origin = origin
			return &cp
		}
		return ae
	}
	return &AHError{Type: ExInternal, Msg: err.Error(), Origin: origin}
}

// ErrorMessageDTO is the JSON error body (eu.arrowhead.dto.ErrorMessageDTO).
type ErrorMessageDTO struct {
	ErrorMessage  string `json:"errorMessage"`
	ErrorCode     int    `json:"errorCode"`
	ExceptionType ExType `json:"exceptionType"`
	Origin        string `json:"origin,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeError(w http.ResponseWriter, err error, defaultOrigin string) {
	ae, ok := err.(*AHError)
	if !ok {
		ae = &AHError{Type: ExInternal, Msg: err.Error()}
	}
	origin := ae.Origin
	if origin == "" {
		origin = defaultOrigin
	}
	writeJSON(w, ae.Type.status(), ErrorMessageDTO{
		ErrorMessage:  ae.Msg,
		ErrorCode:     ae.Type.status(),
		ExceptionType: ae.Type,
		Origin:        origin,
	})
}
