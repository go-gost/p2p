package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-gost/p2p"
	"github.com/goccy/go-yaml"
)

// config is the CLI's own file format: the endpoint configuration (inlined, so
// its keys keep their top-level names) plus the deployment settings the library
// deliberately does not carry — the control-plane listen address, its token,
// and the logger.
type config struct {
	p2p.Config `yaml:",inline"`

	// KeyHex is the removed pre-merge spelling. It is parsed only so an old
	// config fails loudly instead of silently generating a new identity.
	KeyHex string `yaml:"keyHex,omitempty"`

	Addr  string     `yaml:"addr,omitempty"`
	Token string     `yaml:"token,omitempty"`
	Log   *logConfig `yaml:"log,omitempty"`
}

// logConfig mirrors the --log.* flags plus file rotation.
type logConfig struct {
	Level    string             `yaml:"level,omitempty"`
	Format   string             `yaml:"format,omitempty"`
	Output   string             `yaml:"output,omitempty"`
	Rotation *logRotationConfig `yaml:"rotation,omitempty"`
}

// logRotationConfig configures lumberjack file rotation for a file output.
// Zero values fall back to lumberjack's defaults (100 MB, keep all, UTC, no
// compression).
type logRotationConfig struct {
	MaxSize    int  `yaml:"maxSize,omitempty"`
	MaxAge     int  `yaml:"maxAge,omitempty"`
	MaxBackups int  `yaml:"maxBackups,omitempty"`
	LocalTime  bool `yaml:"localTime,omitempty"`
	Compress   bool `yaml:"compress,omitempty"`
}

// loadConfig reads and parses a YAML config file.
func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.KeyHex != "" {
		return nil, fmt.Errorf("config: keyHex was merged into key; use key for the hex identity or a key-file path")
	}
	return &c, nil
}

// ensureIdentity makes the CLI's key file exist before endpoint.New reads it.
// The library only consumes an identity, so the CLI owns generation and the
// default location; this preserves the standalone command's "created if
// missing" behavior without putting file management back into p2p. A
// 64-character hex Key is already in memory and needs no file, and stub mode
// (no DERP) has no identity at all.
func ensureIdentity(c *config) error {
	if c.Derp == "" {
		return nil
	}
	c.Key = strings.TrimSpace(c.Key)
	if p2p.IsHexKey(c.Key) {
		return nil
	}
	if c.Key == "" {
		c.Key = defaultKeyPath()
	}
	if _, err := os.Stat(c.Key); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	hexKey, _, err := p2p.GenerateKey()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.Key), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(c.Key, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		// Another process created it between the stat and the open.
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := f.WriteString(hexKey + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// defaultKeyPath is the CLI's standalone identity location. p2p no longer
// chooses one: embedders such as wisper own their key path.
func defaultKeyPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "p2p", "key-v1")
	}
	return "p2p-key-v1"
}
