module poolreachfixture

go 1.21

// The offline gocron stub of ../fixture gives NewTask its real package
// identity.
require github.com/go-co-op/gocron/v2 v2.0.0

replace github.com/go-co-op/gocron/v2 => ../fixture/stubgocron
