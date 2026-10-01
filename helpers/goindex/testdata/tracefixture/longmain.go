package tracefixture

import (
	"context"
	"log"
	"net/http"
	"time"
)

// longSetup is longer than the snippet budget, and the call sits in a handler
// literal at the bottom of it. The enclosing source sent with the site must
// be the literal, deadline included, not the head of the declaration.
func longSetup(mux *http.ServeMux) {
	log.Printf("starting subsystem %d", 0)
	log.Printf("starting subsystem %d", 1)
	log.Printf("starting subsystem %d", 2)
	log.Printf("starting subsystem %d", 3)
	log.Printf("starting subsystem %d", 4)
	log.Printf("starting subsystem %d", 5)
	log.Printf("starting subsystem %d", 6)
	log.Printf("starting subsystem %d", 7)
	log.Printf("starting subsystem %d", 8)
	log.Printf("starting subsystem %d", 9)
	log.Printf("starting subsystem %d", 10)
	log.Printf("starting subsystem %d", 11)
	log.Printf("starting subsystem %d", 12)
	log.Printf("starting subsystem %d", 13)
	log.Printf("starting subsystem %d", 14)
	log.Printf("starting subsystem %d", 15)
	log.Printf("starting subsystem %d", 16)
	log.Printf("starting subsystem %d", 17)
	log.Printf("starting subsystem %d", 18)
	log.Printf("starting subsystem %d", 19)
	log.Printf("starting subsystem %d", 20)
	log.Printf("starting subsystem %d", 21)
	log.Printf("starting subsystem %d", 22)
	log.Printf("starting subsystem %d", 23)
	log.Printf("starting subsystem %d", 24)
	log.Printf("starting subsystem %d", 25)
	log.Printf("starting subsystem %d", 26)
	log.Printf("starting subsystem %d", 27)
	log.Printf("starting subsystem %d", 28)
	log.Printf("starting subsystem %d", 29)
	log.Printf("starting subsystem %d", 30)
	log.Printf("starting subsystem %d", 31)
	log.Printf("starting subsystem %d", 32)
	log.Printf("starting subsystem %d", 33)
	log.Printf("starting subsystem %d", 34)
	log.Printf("starting subsystem %d", 35)
	log.Printf("starting subsystem %d", 36)
	log.Printf("starting subsystem %d", 37)
	log.Printf("starting subsystem %d", 38)
	log.Printf("starting subsystem %d", 39)
	log.Printf("starting subsystem %d", 40)
	log.Printf("starting subsystem %d", 41)
	log.Printf("starting subsystem %d", 42)
	log.Printf("starting subsystem %d", 43)
	log.Printf("starting subsystem %d", 44)
	log.Printf("starting subsystem %d", 45)
	log.Printf("starting subsystem %d", 46)
	log.Printf("starting subsystem %d", 47)
	log.Printf("starting subsystem %d", 48)
	log.Printf("starting subsystem %d", 49)
	log.Printf("starting subsystem %d", 50)
	log.Printf("starting subsystem %d", 51)
	log.Printf("starting subsystem %d", 52)
	log.Printf("starting subsystem %d", 53)
	log.Printf("starting subsystem %d", 54)
	log.Printf("starting subsystem %d", 55)
	log.Printf("starting subsystem %d", 56)
	log.Printf("starting subsystem %d", 57)
	log.Printf("starting subsystem %d", 58)
	log.Printf("starting subsystem %d", 59)
	log.Printf("starting subsystem %d", 60)
	log.Printf("starting subsystem %d", 61)
	log.Printf("starting subsystem %d", 62)
	log.Printf("starting subsystem %d", 63)
	log.Printf("starting subsystem %d", 64)
	log.Printf("starting subsystem %d", 65)
	log.Printf("starting subsystem %d", 66)
	log.Printf("starting subsystem %d", 67)
	log.Printf("starting subsystem %d", 68)
	log.Printf("starting subsystem %d", 69)
	log.Printf("starting subsystem %d", 70)
	log.Printf("starting subsystem %d", 71)
	log.Printf("starting subsystem %d", 72)
	log.Printf("starting subsystem %d", 73)
	log.Printf("starting subsystem %d", 74)
	log.Printf("starting subsystem %d", 75)
	log.Printf("starting subsystem %d", 76)
	log.Printf("starting subsystem %d", 77)
	log.Printf("starting subsystem %d", 78)
	log.Printf("starting subsystem %d", 79)
	log.Printf("starting subsystem %d", 80)
	log.Printf("starting subsystem %d", 81)
	log.Printf("starting subsystem %d", 82)
	log.Printf("starting subsystem %d", 83)
	log.Printf("starting subsystem %d", 84)
	log.Printf("starting subsystem %d", 85)
	log.Printf("starting subsystem %d", 86)
	log.Printf("starting subsystem %d", 87)
	log.Printf("starting subsystem %d", 88)
	log.Printf("starting subsystem %d", 89)
	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", r.FormValue("url"), nil)
		if err != nil {
			return
		}
		client := &http.Client{}
		client.Do(req)
	})
}

// A short function keeps the whole declaration, so a deadline derived before
// a closure stays in scope of the call inside it.
func shortSetup(req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	func() {
		client := &http.Client{}
		client.Do(req)
	}()
}
