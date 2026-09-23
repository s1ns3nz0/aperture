package challenger

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/stretchr/testify/require"
)

func TestInvoiceCheckObservation(t *testing.T) {
	for _, strict := range []bool{false, true} {
		c := &LndChallenger{strictVerify: strict, invoicesCond: sync.NewCond(&sync.Mutex{}), invoiceStates: map[lntypes.Hash]lnrpc.Invoice_InvoiceState{}, quit: make(chan struct{})}
		require.Equal(t, strict, c.InvoiceCheckEnabled())
		require.Equal(t, strict, (&LNCChallenger{lndChallenger: c}).InvoiceCheckEnabled())
		err := c.VerifyInvoiceStatus(lntypes.ZeroHash, lnrpc.Invoice_SETTLED, time.Millisecond)
		if !strict {
			require.NoError(t, err)
			continue
		}
		var classified *InvoiceStatusError
		require.True(t, errors.As(err, &classified))
		require.Equal(t, "invoice_not_found", classified.Reason)
		c.invoiceStates[lntypes.ZeroHash] = lnrpc.Invoice_OPEN
		err = c.VerifyInvoiceStatus(lntypes.ZeroHash, lnrpc.Invoice_SETTLED, time.Millisecond)
		require.True(t, errors.As(err, &classified))
		require.Equal(t, "invoice_state_mismatch", classified.Reason)
		c.invoiceStates[lntypes.ZeroHash] = lnrpc.Invoice_SETTLED
		require.NoError(t, c.VerifyInvoiceStatus(lntypes.ZeroHash, lnrpc.Invoice_SETTLED, time.Millisecond))
		close(c.quit)
		delete(c.invoiceStates, lntypes.ZeroHash)
		err = c.VerifyInvoiceStatus(lntypes.ZeroHash, lnrpc.Invoice_SETTLED, time.Millisecond)
		require.True(t, errors.As(err, &classified))
		require.Equal(t, "checker_stopped", classified.Reason)
	}
}
