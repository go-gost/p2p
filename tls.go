package p2p

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"
)

// buildTLSConfig mirrors gost's TLS dialer options for the relay connection:
// secure=false skips certificate verification (InsecureSkipVerify), caFile
// adds a PEM CA (e.g. the relay's self-signed cert) to the trusted roots.
// Returns nil when defaults suffice (secure, no CA) so derpclient uses Go's
// normal verification.
func buildTLSConfig(secure bool, caFile string) *tls.Config {
	if secure && caFile == "" {
		return nil
	}
	cfg := &tls.Config{InsecureSkipVerify: !secure}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			slog.Error("load CA", "file", caFile, "error", err)
			return cfg
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			slog.Error("load CA", "file", caFile, "error", "no PEM certificates found")
			return cfg
		}
		cfg.RootCAs = pool
	}
	return cfg
}
