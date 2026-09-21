package main

import (
	"path/filepath"
	"testing"

	"github.com/go-gost/p2p"
	"gopkg.in/natefinch/lumberjack.v2"
)

// TestLogOutputRotation verifies the log.rotation config reaches lumberjack's
// fields, and that a nil rotation falls back to lumberjack defaults.
func TestLogOutputRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "app.log")

	w, err := logOutput(path, &p2p.LogRotationConfig{
		MaxSize: 25, MaxAge: 3, MaxBackups: 2, LocalTime: true, Compress: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	lj, ok := w.(*lumberjack.Logger)
	if !ok {
		t.Fatalf("logOutput = %T, want *lumberjack.Logger", w)
	}
	if lj.Filename != path || lj.MaxSize != 25 || lj.MaxAge != 3 ||
		lj.MaxBackups != 2 || !lj.LocalTime || !lj.Compress {
		t.Fatalf("lumberjack = %+v", lj)
	}

	// nil rotation -> lumberjack defaults (zero MaxSize = default 100 MB)
	w2, err := logOutput(filepath.Join(dir, "def.log"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if lj2 := w2.(*lumberjack.Logger); lj2.MaxSize != 0 || lj2.MaxBackups != 0 || lj2.Compress {
		t.Fatalf("nil rotation lumberjack = %+v", lj2)
	}

	// non-file output is not a lumberjack logger
	if _, err := logOutput("stderr", &p2p.LogRotationConfig{MaxSize: 1}); err != nil {
		t.Fatal(err)
	}
}
