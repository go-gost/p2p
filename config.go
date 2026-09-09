package main

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

// Config is the optional YAML configuration file. Every field mirrors a
// command-line flag (the flag name without the leading "--"); a config value
// supplies the default and an explicitly-set flag overrides it.
type Config struct {
	Addr     string          `yaml:"addr,omitempty"`
	Bind     string          `yaml:"bind,omitempty"`
	Token    string          `yaml:"token,omitempty"`
	Derp     string          `yaml:"derp,omitempty"`
	Key      string          `yaml:"key,omitempty"`
	Target   string          `yaml:"target,omitempty"`
	Stun     string          `yaml:"stun,omitempty"`
	TLS      *TLSConfig      `yaml:"tls,omitempty"`
	Log      *LogConfig      `yaml:"log,omitempty"`
	Forwards []ForwardConfig `yaml:"forwards,omitempty"`
}

// TLSConfig mirrors the --tls.* flags. Secure is a pointer so an omitted
// "secure" (default true) is distinguishable from an explicit "secure: false".
type TLSConfig struct {
	Secure *bool  `yaml:"secure,omitempty"`
	CAFile string `yaml:"caFile,omitempty"`
}

// LogConfig mirrors the --log.* flags plus file rotation.
type LogConfig struct {
	Level    string             `yaml:"level,omitempty"`
	Format   string             `yaml:"format,omitempty"`
	Output   string             `yaml:"output,omitempty"`
	Rotation *LogRotationConfig `yaml:"rotation,omitempty"`
}

// LogRotationConfig configures lumberjack file rotation for a file output.
// Zero values fall back to lumberjack's defaults (100 MB, keep all, UTC, no
// compression).
type LogRotationConfig struct {
	MaxSize    int  `yaml:"maxSize,omitempty"`
	MaxAge     int  `yaml:"maxAge,omitempty"`
	MaxBackups int  `yaml:"maxBackups,omitempty"`
	LocalTime  bool `yaml:"localTime,omitempty"`
	Compress   bool `yaml:"compress,omitempty"`
}

// ForwardConfig is a pre-configured static port forward: bind Listen and bridge
// accepted connections to the peer's public key.
type ForwardConfig struct {
	Listen string `yaml:"listen,omitempty"`
	Peer   string `yaml:"peer,omitempty"`
}

// loadConfig reads and parses a YAML config file.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}
