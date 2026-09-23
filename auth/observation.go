package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/lightninglabs/aperture/mint"
	"github.com/lightninglabs/aperture/securitylog"
)

// Observation is request-local and has exactly one final L402 decision. No
// layer emits it until all authentication schemes have been considered.
type Observation struct {
	Authorization securitylog.Detail
	Settlement    *securitylog.Detail
}

type observedMinter interface {
	VerifyL402Observed(context.Context, *mint.VerificationParams) (mint.VerificationResult, error)
}

// FreshChallengeObserved captures mint results without emitting an issuance
// event before the proxy has decided to send the challenge to the client.
func FreshChallengeObserved(a Authenticator, service string, prices ChallengePrices) (http.Header, []securitylog.Detail, error) {
	switch a := a.(type) {
	case *L402Authenticator:
		var d securitylog.Detail
		h, err := a.freshChallengeHeader(service, prices.Charge, &d)
		return h, []securitylog.Detail{d}, err
	case *MultiAuthenticator:
		var details []securitylog.Detail
		h, err := a.freshChallengeHeaderWithPrices(service, prices, &details)
		return h, details, err
	default:
		if priced, ok := a.(PricedChallenger); ok {
			h, err := priced.FreshChallengeHeaderWithPrices(service, prices)
			return h, nil, err
		}
		h, err := a.FreshChallengeHeader(service, prices.Charge)
		return h, nil, err
	}
}

// AcceptObserved preserves dispatch order. If another scheme wins, a failed
// L402 attempt is not reported as a request denial. Its reason is retained as
// an allowlisted l402_reason, including internal processing errors.
func AcceptObserved(a Authenticator, header *http.Header, service, scheme string) (bool, *Observation) {
	switch a := a.(type) {
	case *L402Authenticator:
		o := &Observation{}
		ok := a.accept(header, service, o)
		return ok, o
	case *MultiAuthenticator:
		var observation *Observation
		for _, child := range a.authenticators {
			if !schemeMatches(child, scheme) {
				continue
			}
			accepted, o := AcceptObserved(child, header, service, "")
			if o != nil && (observation == nil || accepted) {
				observation = o
			}
			if accepted {
				if observation != nil && observation.Authorization.Outcome != "accepted" {
					observation.Authorization.Outcome = "not_applicable"
					observation.Authorization.L402Reason = observation.Authorization.Reason
					observation.Authorization.Reason = "accepted_other_scheme"
				}
				return true, observation
			}
		}
		return false, observation
	default:
		return a.Accept(header, service), nil
	}
}

func settlementDetail(checker InvoiceChecker, err error) securitylog.Detail {
	d := securitylog.Detail{Kind: "l402.settlement", Outcome: "unknown", Reason: "check_status_unknown", ObservedAt: time.Now()}
	if err != nil {
		d.Outcome, d.Reason, d.Internal = "error", "invoice_check_error", true
		var classified interface{ InvoiceCheckReason() string }
		if errors.As(err, &classified) {
			switch classified.InvoiceCheckReason() {
			case "invoice_state_mismatch":
				d.Outcome, d.Reason, d.Internal = "mismatch", "invoice_state_mismatch", false
			case "invoice_not_found":
				d.Reason = "invoice_not_found"
			case "checker_stopped":
				d.Reason = "checker_stopped"
			}
		}
		return d
	}
	if c, ok := checker.(interface{ InvoiceCheckEnabled() bool }); ok {
		if c.InvoiceCheckEnabled() {
			d.Outcome, d.Reason = "settled", "settled"
		} else {
			d.Outcome, d.Reason = "skipped", "verification_disabled"
		}
	}
	return d
}
