// Package rate is an offline stub of golang.org/x/time/rate: the signatures
// the fixture calls, no behaviour.
package rate

import (
	"context"
	"time"
)

type Limit float64

type Limiter struct{ limit Limit }

type Reservation struct{}

func NewLimiter(r Limit, b int) *Limiter { return &Limiter{limit: r} }

func (l *Limiter) Allow() bool                    { return true }
func (l *Limiter) AllowN(t time.Time, n int) bool { return true }
func (l *Limiter) Wait(ctx context.Context) error { return nil }
func (l *Limiter) Reserve() *Reservation          { return &Reservation{} }
func (l *Limiter) Limit() Limit                   { return l.limit }
