// Package prometheus is an offline stub of the metric constructors of
// github.com/prometheus/client_golang/prometheus. It gives the fixture the
// real package identity for type-driven detection with no network dependency.
package prometheus

type Opts struct {
	Name string
	Help string
}

type (
	GaugeOpts     Opts
	CounterOpts   Opts
	HistogramOpts Opts
)

type Gauge interface{ Set(float64) }
type Counter interface{ Add(float64) }
type Histogram interface{ Observe(float64) }

type CounterVec struct{}

type metric struct{}

func (metric) Set(float64)     {}
func (metric) Add(float64)     {}
func (metric) Observe(float64) {}

func NewGauge(GaugeOpts) Gauge                        { return metric{} }
func NewCounter(CounterOpts) Counter                  { return metric{} }
func NewCounterVec(CounterOpts, []string) *CounterVec { return &CounterVec{} }
func NewHistogram(HistogramOpts) Histogram            { return metric{} }
