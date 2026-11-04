package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-co-op/gocron/v2"
)

// One entry of each kind reaches the pool. The comment on each says which.

// Counter is called through an interface, so the call reaches (*Store).Count
// by interface dispatch only.
type Counter interface{ Count(ctx context.Context) }

type api struct{ c Counter }

func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) { // handler: http_handler
	a.c.Count(r.Context())
}

type handlers struct{ s *Store }

func (h *handlers) rename(w http.ResponseWriter, r *http.Request) { // handler: route
	h.s.Rename(r.Context())
}

// AdminServer and RegisterAdminServer have the shape of generated gRPC code.
type AdminServer interface {
	Purge(ctx context.Context) error
}

type grpcServer struct{}

func RegisterAdminServer(s *grpcServer, srv AdminServer) {}

type admin struct{ s *Store }

func (a *admin) Purge(ctx context.Context) error { // handler: grpc
	a.s.Count(ctx)
	return nil
}

func (a *admin) helper(ctx context.Context) { a.s.Count(ctx) }

func flushLoop(ctx context.Context, s *Store) { // job: go,ticker flushLoop
	t := time.NewTicker(time.Minute)
	for range t.C {
		s.Count(ctx)
	}
}

// newPoller stores a ticker and starts the loop that reads it: the loop is
// the job, the constructor is not.
type poller struct {
	t *time.Ticker
	s *Store
}

func newPoller(s *Store) *poller {
	p := &poller{t: time.NewTicker(time.Second), s: s}
	go p.run()
	return p
}

func (p *poller) run() { // job: go,ticker run
	for range p.t.C {
		p.s.Count(context.Background())
	}
}

// tick is a ticker loop no goroutine in this repository starts.
func tick(s *Store) { // job: ticker
	for range time.Tick(time.Second) {
		s.Compact()
	}
}

// A second pool, reached by a goroutine only.
func poll(c *http.Client) { // job: go poll
	c.Get("http://localhost/health") // site: client
}

func main() {
	ctx := context.Background()
	db, err := openPool("file::memory:")
	if err != nil {
		return
	}
	store := NewStore(db)
	go flushLoop(ctx, store)
	newPoller(store)
	tick(store)
	admin := &admin{s: store}
	admin.helper(ctx)
	go func() { // job: go_literal
		store.Count(ctx)
	}()
	s, _ := gocron.NewScheduler()
	s.NewJob(gocron.DurationJob(time.Hour), gocron.NewTask(store.Compact))
	store.Exported(ctx, db)
	useSpare(ctx)

	mux := http.NewServeMux()
	h := &handlers{s: store}
	mux.HandleFunc("/rename", h.rename)
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) { // handler: route_literal
		store.Count(r.Context())
	})
	RegisterAdminServer(&grpcServer{}, admin)
	client := &http.Client{Timeout: time.Second}
	go poll(client)
	http.ListenAndServe(":8080", &api{c: store})
}
