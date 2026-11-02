package constructionfixture

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
)

// The five shapes of a TLS setting that skips verification, from the code
// they were measured in. Each skip sits in a function, or behind a field,
// whose name says it is deliberate, the way CodeQL's
// go/disabled-certificate-check reads names: testdata is not test code to it.

type options struct {
	Insecure         bool
	SSLVerify        bool
	SkipVerify       bool
	UseTLS           bool
	InsecureIfPinned bool
}

// The chain is re-verified, without the hostname, by VerifyPeerCertificate.
func Reverified(roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		RootCAs:            roots,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			return nil
		},
	}
}

// Dials its own local listener: unconditional, nothing re-verifies.
func InsecureLoopback() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

// A literal behind an equality on an option field, nested in another if.
func OptedOut(t *options, ca string) *tls.Config {
	if len(ca) <= 0 {
		if t.Insecure == true {
			return &tls.Config{InsecureSkipVerify: true}
		}
		return nil
	}
	return &tls.Config{}
}

// An assignment behind a negated option field.
func NotVerified(o options, cfg *tls.Config) {
	if !o.SSLVerify {
		cfg.InsecureSkipVerify = true
	}
}

// A literal nested in a transport, behind an option field.
func Skipped(o options) *http.Client {
	if o.SkipVerify {
		return &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
	}
	return http.DefaultClient
}

// The else branch runs when the option is off.
func Verified(o options, cfg *tls.Config) {
	if o.SSLVerify {
		cfg.ServerName = "db"
	} else {
		cfg.InsecureSkipVerify = true
	}
}

// A closure built under an if runs wherever it is called.
func DeferredInsecure(o options) func() *tls.Config {
	if o.Insecure {
		return func() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
	}
	return nil
}

// The caller's own argument turns verification off, alone or with another
// test.
func DialInsecure(addr string, insecure bool) *tls.Config {
	if addr != "" && insecure {
		return &tls.Config{InsecureSkipVerify: true}
	}
	return &tls.Config{}
}

// A local computed in the function is not an option.
func InsecureFromEnv(env func(string) string) *tls.Config {
	skip := env("TLS_SKIP") != ""
	if skip {
		return &tls.Config{InsecureSkipVerify: true}
	}
	return &tls.Config{}
}

// An option outside, an if on a local's type assertion inside: the option
// still holds the assignment.
func NestedOptOut(o options, rt http.RoundTripper) http.RoundTripper {
	if o.Insecure {
		if t, ok := rt.(*http.Transport); ok {
			t = t.Clone()
			t.TLSClientConfig.InsecureSkipVerify = true
			return t
		}
	}
	return rt
}

// Set only when a pinned chain is configured, on a config whose
// VerifyPeerCertificate checks the pin.
func Pinned(o options, pinned []byte, verify func([][]byte, [][]*x509.Certificate) error) *tls.Config {
	config := &tls.Config{
		VerifyPeerCertificate: verify,
	}
	if o.InsecureIfPinned && pinned != nil {
		config.InsecureSkipVerify = true
	}
	return config
}

// The option turns TLS on, and the only TLS it turns on skips verification:
// the option is the insecure mode, not an opt-out of a verified one.
func DialTLS(o options) *tls.Config {
	if o.UseTLS {
		return &tls.Config{InsecureSkipVerify: true}
	}
	return nil
}
