package constructionfixture

import (
	"crypto/cipher"
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

// The cipher is the site; nothing here encrypts with it.
func Block(key []byte) (cipher.Block, error) {
	return des.NewCipher(key)
}

func Digest(b []byte) [16]byte {
	return md5.Sum(b)
}

func Open() (*sql.DB, error) {
	return sql.Open("postgres", "postgres://app:hunter2@db/app")
}
