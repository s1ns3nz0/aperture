package securitylog

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

var benchmarkCredential, benchmarkPayment string

// BenchmarkReferences includes both domains and their hex/string encoding.
// The HMAC baseline reproduces the previous implementation, not raw hash speed.
func BenchmarkReferences(b *testing.B) {
	id := append([]byte{0, 0}, bytes.Repeat([]byte{7}, 64)...)
	e := &Emitter{}
	b.Run("SHA256", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchmarkCredential, benchmarkPayment = e.references(id)
		}
	})
	b.Run("HMAC_SHA256_baseline", func(b *testing.B) {
		key := bytes.Repeat([]byte{1}, 32)
		ref := func(domain string, value []byte) string {
			m := hmac.New(sha256.New, key)
			_, _ = m.Write([]byte("aperture/security/v1/" + domain + "\x00"))
			_, _ = m.Write(value)
			return "hmac:" + hex.EncodeToString(m.Sum(nil))
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchmarkCredential = ref("credential", id[34:66])
			benchmarkPayment = ref("payment", id[2:34])
		}
	})
}
