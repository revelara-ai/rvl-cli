package main

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

var limiter = rate.NewLimiter(10, 20)

// handle refuses work over the limit: the refusal is this function's branch.
func handle(w http.ResponseWriter, r *http.Request) {
	if !limiter.Allow() { // site: allow
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// guarded embeds the limiter, so its methods are the limiter's.
type guarded struct {
	*rate.Limiter
}

func drain(ctx context.Context, g guarded, jobs <-chan func()) error {
	for job := range jobs {
		if err := g.Wait(ctx); err != nil { // site: wait
			return err
		}
		job()
	}
	_ = g.Limit() // not a decision
	return nil
}

// local is not a limiter of the table, whatever its method is called.
type local struct{}

func (local) Allow() bool { return true }

func main() {
	_ = local{}.Allow()
	_ = limiter.AllowN(time.Now(), 3) // site: allown
	http.HandleFunc("/", handle)
	_ = http.ListenAndServe(":8080", nil)
}
