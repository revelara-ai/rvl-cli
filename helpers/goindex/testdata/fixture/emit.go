package fixture

import (
	"context"
	"log/slog"
)

// Emitter exercises the G4 emission inventory: three slog.Logger method
// calls must aggregate to ONE emission packet with count 3, and the two
// package-level slog calls to a separate log/slog aggregate with count 2.
func Emitter(ctx context.Context) {
	slog.Info("start")
	slog.Debug("detail")
	logger := slog.Default()
	logger.Warn("w1")
	logger.Error("e1")
	logger.InfoContext(ctx, "done")
}

// Swallow recovers a panic and emits nothing: the recover_block swallow
// aggregate (an error path with no capture or log emission).
func Swallow() {
	defer func() {
		_ = recover()
	}()
}

// Recovered recovers AND logs: an instrumented error path, NOT a swallow.
func Recovered() {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("recovered", "panic", r)
		}
	}()
}
