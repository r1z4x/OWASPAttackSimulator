module github.com/owaspchecker/pkg/engine

go 1.23

require (
	github.com/owaspchecker/pkg/common v0.0.0
	github.com/owaspchecker/pkg/mutate v0.0.0
	github.com/owaspchecker/pkg/checks v0.0.0
	github.com/owaspchecker/pkg/httpx v0.0.0
	github.com/owaspchecker/pkg/store v0.0.0
)

replace (
	github.com/owaspchecker/pkg/common => ../common
	github.com/owaspchecker/pkg/mutate => ../mutate
	github.com/owaspchecker/pkg/checks => ../checks
	github.com/owaspchecker/pkg/httpx => ../httpx
	github.com/owaspchecker/pkg/store => ../store
)
