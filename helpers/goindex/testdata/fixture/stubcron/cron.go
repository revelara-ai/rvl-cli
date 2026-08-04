// Package cron is a minimal offline STUB of github.com/robfig/cron/v3, wired
// into the fixture via a go.mod replace directive. Just enough surface for the
// fixture to type-check so goindex's type-driven job-registration detection
// (which keys on the RESOLVED package path) has a real robfig/cron identity to
// resolve — no network, no vendoring.
package cron

// EntryID identifies a registered entry, as in the real library.
type EntryID int

// Cron keeps a registry of scheduled jobs.
type Cron struct{}

// New returns a new Cron job runner.
func New() *Cron { return &Cron{} }

// AddFunc registers cmd to run on the given schedule.
func (c *Cron) AddFunc(spec string, cmd func()) (EntryID, error) {
	_ = spec
	_ = cmd
	return 0, nil
}

// Start begins running the scheduled jobs.
func (c *Cron) Start() {}
