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
// normal verification. A CA that cannot be loaded is logged and ignored (the
// relay's own handshake then fails against the default roots); log is the
// host's logger, defaulting to slog.Default().
func buildTLSConfig(secure bool, caFile string, log *slog.Logger) *tls.Config {
	if log == nil {
		log = slog.Default()
	}
	if secure && caFile == "" {
		return nil
	}
	cfg := &tls.Config{InsecureSkipVerify: !secure}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			log.Error("load CA", "file", caFile, "error", err)
			return cfg
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			log.Error("load CA", "file", caFile, "error", "no PEM certificates found")
			return cfg
		}
		cfg.RootCAs = pool
	}
	return cfg
}
