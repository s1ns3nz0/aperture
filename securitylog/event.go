// Package securitylog emits the opt-in, bounded L402 security event stream.
// It is independent of application logging and never accepts raw error text.
package securitylog

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"time"
)

// Event is the version 1 collector contract. References are SHA-256 digests, never
// credentials. CredentialVerified describes identity validation, not payment.
type Event struct {
	SchemaVersion      int       `json:"schema_version"`
	Timestamp          time.Time `json:"timestamp"`
	Level              string    `json:"level"`
	Category           string    `json:"category"`
	Event              string    `json:"event"`
	RequestID          string    `json:"request_id"`
	Service            string    `json:"service"`
	Method             string    `json:"method"`
	SourceIP           string    `json:"source_ip,omitempty"`
	Outcome            string    `json:"outcome"`
	Reason             string    `json:"reason"`
	L402Reason         string    `json:"l402_reason,omitempty"`
	CredentialRef      string    `json:"credential_ref,omitempty"`
	PaymentRef         string    `json:"payment_ref,omitempty"`
	CredentialVerified bool      `json:"credential_verified"`
}

// Detail carries only fixed reason codes and a bounded token identifier.
// Identifier is never serialized; Record turns its components into references.
type Detail struct {
	Kind, Outcome, Reason, L402Reason string
	Internal, Verified                bool
	Identifier                        []byte
	ObservedAt                        time.Time
}

// Trace owns server-generated correlation metadata for one request.
type Trace struct {
	emitter *Emitter
	base    Event
}

// Begin never uses client-provided request IDs or forwarding headers.
func (e *Emitter) Begin(service, method, remoteAddr string) *Trace {
	if e == nil {
		return nil
	}
	if len(service) > 128 {
		service = service[:128]
	}
	switch method {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH":
	default:
		method = "OTHER"
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := ""
	if parsed := net.ParseIP(host); parsed != nil {
		ip = parsed.String()
	}
	return &Trace{emitter: e, base: Event{
		SchemaVersion: 1, Category: "security", RequestID: rand.Text(),
		Service: service, Method: method, SourceIP: ip,
	}}
}

// Record excludes unknown codes rather than accidentally logging error text.
func (t *Trace) Record(d Detail) {
	if t == nil {
		return
	}
	if !validKind(d.Kind) || !validOutcome(d.Outcome) || !validReason(d.Reason) ||
		(d.L402Reason != "" && !validReason(d.L402Reason)) {
		t.emitter.dropped.Add(1)
		return
	}
	e := t.base
	e.Timestamp = time.Now().UTC()
	if !d.ObservedAt.IsZero() {
		e.Timestamp = d.ObservedAt.UTC()
	}
	e.Level = "INFO"
	if d.Internal {
		e.Level = "ERROR"
	}
	e.Event, e.Outcome, e.Reason = d.Kind, d.Outcome, d.Reason
	e.L402Reason = d.L402Reason
	e.CredentialRef, e.PaymentRef = t.emitter.references(d.Identifier)
	e.CredentialVerified = d.Verified && e.CredentialRef != ""
	t.emitter.emit(e)
}

func (e *Emitter) references(id []byte) (string, string) {
	// v0 identifier: version (2), bound payment hash (32), token ID (32).
	// Do not use DecodeIdentifier's permissive short-read behavior here.
	if len(id) != 66 || id[0] != 0 || id[1] != 0 {
		return "", ""
	}
	ref := func(domain string, value []byte) string {
		// The input is bounded to a fixed domain and one 32-byte component.
		input := append([]byte("aperture/security/v1/"+domain+"\x00"), value...)
		sum := sha256.Sum256(input)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	return ref("credential", id[34:66]), ref("payment", id[2:34])
}

func validKind(v string) bool {
	return v == "l402.authorization" || v == "l402.challenge" || v == "l402.settlement"
}

func validOutcome(v string) bool {
	switch v {
	case "accepted", "denied", "not_applicable", "issued", "error", "settled", "skipped", "unknown", "mismatch":
		return true
	}
	return false
}

func validReason(v string) bool {
	switch v {
	case "accepted", "missing_credentials", "malformed_credentials", "malformed_identifier",
		"payment_proof_mismatch", "unknown_credential", "secret_store_error",
		"invalid_signature", "restriction_failure", "processing_error",
		"accepted_other_scheme", "settled", "verification_disabled", "invoice_state_mismatch",
		"invoice_not_found", "invoice_check_error", "checker_stopped", "check_status_unknown",
		"challenge_issued", "challenge_creation_failed", "challenge_delivery_failed":
		return true
	}
	return false
}
