// Package misuse is the goindex fixture for the misuse lane: an error value
// assigned to the blank identifier.
package misuse

import (
	"encoding/json"
	"os"
	"strconv"
)

type store struct{ f *os.File }

func (s *store) flush() error { return s.f.Sync() }

// CleanUp discards one package-level error twice and one method error once.
func CleanUp(path string, f *os.File) {
	_ = os.Remove(path)
	_ = os.Remove(path + ".tmp")
	_ = f.Close()
}

// Parse discards the error half of a two-value result.
func Parse(raw string) int {
	n, _ := strconv.Atoi(raw)
	return n
}

// Decode keeps the error: not a discard.
func Decode(raw []byte, v any) error {
	err := json.Unmarshal(raw, v)
	return err
}

// Lookup discards a bool and a plain value, not an error.
func Lookup(m map[string]int, raw string) int {
	v, _ := m[raw]
	_ = len(raw)
	return v
}

// Flush discards the error of a method on a local type, inside a deferred
// closure. The packet belongs to the declared function.
func Flush(s *store) {
	defer func() {
		_ = s.flush()
	}()
}

// Dynamic discards the error of a call through a function value.
func Dynamic(fn func() error) {
	_ = fn()
}

// Pair discards two errors in one parallel assignment.
func Pair(a, b string) {
	_, _ = os.Remove(a), os.Remove(b)
}
