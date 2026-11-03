module fixture

go 1.21

// Offline stubs (see stubcron/, stubgocron/): give the fixture real
// robfig/cron and go-co-op/gocron package identities for type-driven
// background-job detection without any network dep.
require (
	github.com/go-co-op/gocron/v2 v2.0.0
	github.com/robfig/cron/v3 v3.0.1
)

replace github.com/robfig/cron/v3 => ./stubcron

replace github.com/go-co-op/gocron/v2 => ./stubgocron
