package mint

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MintResult labels an L402 mint attempt. Using a typed string instead of a
// bare string at call sites means a typo is a compile error, not a silently
// wrong time series.
type MintResult string

const (
	MintOK               MintResult = "ok"
	MintChallengeFailed  MintResult = "challenge_failed"
	MintIdentifierFailed MintResult = "identifier_failed"
	MintSecretFailed     MintResult = "secret_failed"
	MintMacaroonFailed   MintResult = "macaroon_failed"
	MintCaveatFailed     MintResult = "caveat_failed"
)

// VerifyReason labels an L402 verify attempt.
//
// VerifyMacaroonValid and VerifyAccepted are NOT interchangeable: every
// accepted request also passes through VerifyMacaroonValid on its way, so a
// dashboard that sums all reasons to approximate "total requests" will
// double count. VerifyAccepted is the only reason that means a request was
// let through end to end; every other value, including
// VerifyMacaroonValid, is an intermediate checkpoint.
type VerifyReason string

const (
	// VerifyAccepted means auth.Accept let the request through end to
	// end, invoice settlement included. This is the only terminal
	// "success" reason.
	VerifyAccepted VerifyReason = "accepted"

	// VerifyMacaroonValid means mint.VerifyL402 found the macaroon's
	// crypto and caveats to check out. It is a checkpoint, not a final
	// outcome: the caller still has to confirm invoice settlement.
	VerifyMacaroonValid VerifyReason = "macaroon_valid"

	// VerifyMalformedHeader means the request carried no parseable L402
	// credential at all (auth.Accept, before mint.VerifyL402 is even
	// called).
	VerifyMalformedHeader VerifyReason = "malformed_header"

	// VerifyMalformedMacaroon means the macaroon's identifier bytes
	// couldn't be decoded, i.e. the presented macaroon isn't one this
	// mint (or any version it understands) produced.
	VerifyMalformedMacaroon VerifyReason = "malformed_macaroon"

	// VerifyBadPreimage means the presented preimage does not hash to
	// the payment hash bound to the macaroon.
	VerifyBadPreimage VerifyReason = "bad_preimage"

	// VerifySecretNotFound means no secret is on record for this
	// macaroon's identifier hash: it was never minted by us (or its
	// secret already expired/was revoked).
	VerifySecretNotFound VerifyReason = "secret_not_found"

	// VerifySecretLookupError means the secret store returned an error
	// other than "not found" — a backend/storage fault, not evidence of
	// a bad credential. Kept separate from VerifySecretNotFound so an
	// infra outage doesn't read as a wave of forged tokens.
	VerifySecretLookupError VerifyReason = "secret_lookup_error"

	// VerifyBadSignature means the macaroon's HMAC caveat chain doesn't
	// verify against its stored secret.
	VerifyBadSignature VerifyReason = "bad_signature"

	// VerifyCaveatUnsatisfied means the macaroon's crypto is valid but a
	// caveat condition (service, expiration, ...) was not satisfied.
	VerifyCaveatUnsatisfied VerifyReason = "caveat_unsatisfied"

	// VerifyInvoiceUnsettled means the macaroon and preimage both check
	// out, but the underlying invoice is not (yet) recorded as settled.
	VerifyInvoiceUnsettled VerifyReason = "invoice_unsettled"
)

var (
	// l402MintTotal counts L402 mint attempts by result.
	l402MintTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "aperture",
			Subsystem: "l402",
			Name:      "mint_total",
			Help:      "Total L402 mint attempts by result",
		},
		[]string{"result"},
	)

	// l402VerifyTotal counts L402 verify attempts by reason. See
	// VerifyReason's doc comment before summing across label values.
	l402VerifyTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "aperture",
			Subsystem: "l402",
			Name:      "verify_total",
			Help: "Total L402 verify attempts by reason. reason=" +
				"\"macaroon_valid\" is a checkpoint nested " +
				"inside a later \"accepted\", not a distinct " +
				"outcome — sum(rate(...)) over all reasons " +
				"double-counts. \"accepted\" alone is the " +
				"terminal success count.",
		},
		[]string{"reason"},
	)
)

// recordMint increments the mint counter for the given result.
func recordMint(result MintResult) {
	l402MintTotal.WithLabelValues(string(result)).Inc()
}

// recordVerify increments the verify counter for the given reason.
func recordVerify(reason VerifyReason) {
	l402VerifyTotal.WithLabelValues(string(reason)).Inc()
}

// RecordVerifyResult lets other packages (auth) report into the same
// counter for outcomes mint.VerifyL402 itself never observes: a malformed
// header, an unsettled invoice, or final acceptance.
func RecordVerifyResult(reason VerifyReason) {
	recordVerify(reason)
}
