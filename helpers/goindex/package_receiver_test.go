package main

import "testing"

// A package-level call such as http.Get has no receiver value. go/types gives
// the package name the invalid type, and that used to reach the wire as the
// client type "invalid type", so no spec could ever match the site.
func TestPackageLevelCallCarriesThePackagePath(t *testing.T) {
	sites := runRetrieve("testdata/fixture", "fixture")
	var pkgLevel, method []RetrievedSite
	for _, s := range sites {
		if s.Method != "Get" {
			continue
		}
		switch s.Symbol {
		case "FetchPackageLevel":
			pkgLevel = append(pkgLevel, s)
		case "FetchWithClient":
			method = append(method, s)
		}
	}
	if len(pkgLevel) != 1 {
		t.Fatalf("want one package-level Get site, got %+v", pkgLevel)
	}
	if got := pkgLevel[0].ClientType; got != "net/http" {
		t.Fatalf("package-level http.Get must carry client_type net/http, got %q", got)
	}
	if !pkgLevel[0].Prov.ClientTypeKnown {
		t.Fatal("a package path is a resolved identity; ClientTypeKnown must be true")
	}
	if len(method) != 1 || method[0].ClientType != "net/http.Client" {
		t.Fatalf("a method on a client value keeps its type, got %+v", method)
	}
}
