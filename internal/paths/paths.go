package paths

import (
	"os"
	"path/filepath"
)

// DataDir resolves the single directory used for all ShellGate-owned state.
func DataDir(flag string) (string, error) {
	if flag != "" {
		return filepath.Abs(expandHome(flag))
	}
	if v := os.Getenv("SHELLGATE_DATA_DIR"); v != "" {
		return filepath.Abs(expandHome(v))
	}
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, "shellgate"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".local", "share", "shellgate"), nil
}

// Resolve supports absolute, data-dir-relative, and ~/ paths.
func Resolve(dataDir, p string) string {
	if p == "" {
		return ""
	}
	p = expandHome(p)
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(dataDir, p)
}

func expandHome(p string) string {
	if p == "~" || len(p) >= 2 && p[:2] == "~/" {
		if h, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return h
			}
			return filepath.Join(h, p[2:])
		}
	}
	return p
}
