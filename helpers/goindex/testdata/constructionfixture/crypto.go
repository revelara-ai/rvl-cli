package constructionfixture

import (
	"crypto/des"
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"net/http"
)

// The TLS config is a package variable: its line is the violation, and no
// function body holds it.
var insecure = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}

func Client() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: insecure}}
}

func Verify(cfg *tls.Config, skip bool) {
	cfg.InsecureSkipVerify = skip
	cfg.ServerName = "example.com"
}

func Encrypt(key, block []byte) ([]byte, error) {
	c, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(block))
	c.Encrypt(out, block)
	return out, nil
}

func Digest(b []byte) [16]byte {
	return md5.Sum(b)
}

func Open() (*sql.DB, error) {
	return sql.Open("postgres", "postgres://app:hunter2@db/app")
}
