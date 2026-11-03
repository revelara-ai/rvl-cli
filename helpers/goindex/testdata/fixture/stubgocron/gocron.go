// Package gocron is a minimal offline STUB of github.com/go-co-op/gocron/v2,
// wired into the fixture via a go.mod replace directive like stubcron. It has
// the registration shape s.NewJob(gocron.DurationJob(d), gocron.NewTask(f)):
// the job function is the argument of NewTask, not of NewJob.
package gocron

import "time"

// JobDefinition says when a job runs.
type JobDefinition interface{}

// Task is the function a job runs, with its parameters.
type Task func() (any, []any)

// Job is a registered job.
type Job interface{}

// Scheduler runs registered jobs.
type Scheduler interface {
	NewJob(JobDefinition, Task) (Job, error)
	Start()
}

type scheduler struct{}

func (scheduler) NewJob(JobDefinition, Task) (Job, error) { return nil, nil }
func (scheduler) Start()                                  {}

// NewScheduler returns a new Scheduler.
func NewScheduler() (Scheduler, error) { return scheduler{}, nil }

// DurationJob runs a job every d.
func DurationJob(d time.Duration) JobDefinition { return d }

// NewTask wraps function and its parameters as a Task.
func NewTask(function any, parameters ...any) Task {
	return func() (any, []any) { return function, parameters }
}
