package challenger

// InvoiceStatusError distinguishes an observed state mismatch from an
// inability to find or check an invoice. Error text preserves existing logs.
type InvoiceStatusError struct {
	Reason string
	Err    error
}

func (e *InvoiceStatusError) Error() string              { return e.Err.Error() }
func (e *InvoiceStatusError) Unwrap() error              { return e.Err }
func (e *InvoiceStatusError) InvoiceCheckReason() string { return e.Reason }

func (l *LndChallenger) invoiceCheckError(reason string, err error) error {
	select {
	case <-l.quit:
		reason = "checker_stopped"
	default:
	}
	return &InvoiceStatusError{Reason: reason, Err: err}
}

// InvoiceCheckEnabled exposes the strict-verification bypass to observers.
func (l *LndChallenger) InvoiceCheckEnabled() bool { return l.strictVerify }
func (l *LNCChallenger) InvoiceCheckEnabled() bool {
	return l.lndChallenger.InvoiceCheckEnabled()
}
