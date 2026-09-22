package main

import (
	"fmt"
	"os"

	"github.com/go-gost/p2p"
	"github.com/goccy/go-yaml"
)

// config is the CLI's own file format: the endpoint configuration (inlined, so
// its keys keep their top-level names) plus the deployment settings the library
// deliberately does not carry — the control-plane listen address, its token,
// and the logger.
type config struct {
	p2p.Config `yaml:",inline"`

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
	return &c, nil
}
