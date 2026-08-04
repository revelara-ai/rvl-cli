// Background-job surfaces (G3, po-av01j.4): scheduler registrations and a
// ticker-driven worker loop. One cron registration is bare (no bound
// anywhere), one derives its own deadline inside the registered closure —
// the pair the job-altitude timeout judgment must tell apart. They live in
// SEPARATE functions so the bounded closure's deadline cannot leak into the
// bare registration's retrieved scope.
package fixture

import (
	"context"
	"time"

	cron "github.com/robfig/cron/v3"
)

// scheduleHourly is the bare registration: the job body has no deadline of
// any kind.
func scheduleHourly(c *cron.Cron) {
	_, _ = c.AddFunc("@hourly", func() {
		rebuildAll()
	})
	c.Start()
}

// scheduleDaily is the bounded registration: the closure derives its own run
// deadline.
func scheduleDaily(c *cron.Cron) {
	_, _ = c.AddFunc("@daily", func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		pruneOld(ctx)
	})
}

// pollLoop is a ticker-driven worker loop.
func pollLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		rebuildAll()
	}
}

func rebuildAll() {}

func pruneOld(ctx context.Context) { _ = ctx }
