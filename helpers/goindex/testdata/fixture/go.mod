module fixture

go 1.21

// Offline stub (see stubcron/): gives the fixture a real robfig/cron package
// identity for type-driven background-job detection without any network dep.
require github.com/robfig/cron/v3 v3.0.1

replace github.com/robfig/cron/v3 => ./stubcron
