package misuse

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var errDown = errors.New("down")

func call() error { return errDown }

func backoffFor(attempt int) time.Duration { return time.Duration(attempt) * time.Second }

// --- retry_shape (B1/B2) ------------------------------------------------------

// RetryConstant sleeps the same time after each failed attempt.
func RetryConstant() error {
	var err error
	for i := 0; i < 5; i++ {
		if err = call(); err == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return err
}

// RetryForever has a constant delay and no limit on attempts: two shapes.
func RetryForever() {
	for {
		err := call()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		return
	}
}

// RetryExponential grows the delay and adds no random term.
func RetryExponential() error {
	delay := 100 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		if err := call(); err != nil {
			time.Sleep(delay)
			delay *= 2
			continue
		}
		return nil
	}
	return errDown
}

// RetryShifted computes the delay from the loop counter through a local, and
// waits in a select.
func RetryShifted(ctx context.Context) error {
	for attempt := range 4 {
		err := call()
		if err == nil {
			return nil
		}
		wait := time.Duration(1<<attempt) * time.Second
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return errDown
}

// RetryJittered grows the delay and adds a random term: no shape.
func RetryJittered() error {
	delay := 100 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		if err := call(); err != nil {
			time.Sleep(delay + time.Duration(rand.Int63n(int64(delay))))
			delay *= 2
			continue
		}
		return nil
	}
	return errDown
}

// RetryCounted has no loop condition, but a counter in the body limits the
// attempts: the constant delay is the only shape.
func RetryCounted() error {
	attempts := 0
	for {
		err := call()
		if err == nil {
			return nil
		}
		attempts++
		if attempts >= 3 {
			return err
		}
		time.Sleep(time.Second)
	}
}

// RetryOpaque takes the delay from a function. Its shape is not in this
// expression, so nothing is reported.
func RetryOpaque() error {
	for attempt := 0; attempt < 5; attempt++ {
		if err := call(); err != nil {
			time.Sleep(backoffFor(attempt))
			continue
		}
		return nil
	}
	return errDown
}

// PingAll sleeps a constant time in a loop over items. Each item gets one
// attempt: this is not a retry.
func PingAll(hosts []string) {
	for range hosts {
		if err := call(); err != nil {
			time.Sleep(time.Second)
		}
	}
}

// Poll sleeps between rounds of work, not after a failure.
func Poll() {
	for {
		if err := call(); err != nil {
			return
		}
		time.Sleep(time.Minute)
	}
}

// --- sql_concat_in_call (Q4, same expression only) ----------------------------

// FindUser builds the SQL text in the argument of the query call.
func FindUser(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

// DeleteUser formats the SQL text in the argument of the query call.
func DeleteUser(ctx context.Context, tx *sql.Tx, id string) error {
	_, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM users WHERE id = %s", id))
	return err
}

const usersTable = "users"

// SafeQueries passes a value as a parameter, joins constants, and runs text
// that another statement built. The last one is the cross-statement form,
// which is out of scope.
func SafeQueries(db *sql.DB, name string) error {
	rows, err := db.Query("SELECT * FROM "+usersTable+" WHERE name = ?", name)
	if err != nil {
		return err
	}
	q := "SELECT 1 WHERE x = " + name
	row := db.QueryRow(q)
	return errors.Join(rows.Close(), row.Err())
}

// --- print_logging (I1) -------------------------------------------------------

// Report prints to the standard streams.
func Report(n int) {
	fmt.Println("processed", n)
	fmt.Printf("done %d\n", n)
	fmt.Fprintf(os.Stderr, "warn %d\n", n)
	println("debug")
}

// Render writes to a writer it was given and formats a string: not a print.
func Render(w io.Writer, n int) string {
	fmt.Fprintf(w, "%d", n)
	return fmt.Sprintf("%d", n)
}

// --- latency_scalar_metric (J7) -----------------------------------------------

var (
	requestLatency = prometheus.NewGauge(prometheus.GaugeOpts{Name: "http_request_latency_seconds", Help: "mean"})
	durationSum    = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "job_duration_seconds_total"}, []string{"job"})
	queueDepth     = prometheus.NewGauge(prometheus.GaugeOpts{Name: "queue_depth"})
	latencyHist    = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "http_request_duration_seconds"})
)

func registerLate() prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{Name: "db_response_time_ms"})
}

// Observe keeps the metrics in use.
func Observe(d time.Duration) {
	requestLatency.Set(d.Seconds())
	queueDepth.Set(1)
	latencyHist.Observe(d.Seconds())
	_ = durationSum
	registerLate().Set(1)
}
