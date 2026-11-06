package main

import (
	"testing"

	"golang.org/x/time/rate"
)

func TestLimiterRefusesWithNoBurst(t *testing.T) {
	l := rate.NewLimiter(0, 0)
	if l.Allow() { // site: test allow
		t.Fatal("a limiter with no burst must refuse")
	}
}
