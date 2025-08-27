module github.com/owaspattacksimulator/pkg/engine

go 1.23

require (
	github.com/owaspattacksimulator/pkg/common v0.0.0
	github.com/owaspattacksimulator/pkg/mutate v0.0.0
	github.com/owaspattacksimulator/pkg/checks v0.0.0
	github.com/owaspattacksimulator/pkg/httpx v0.0.0
	github.com/owaspattacksimulator/pkg/store v0.0.0
)

replace (
	github.com/owaspattacksimulator/pkg/common => ../common
	github.com/owaspattacksimulator/pkg/mutate => ../mutate
	github.com/owaspattacksimulator/pkg/checks => ../checks
	github.com/owaspattacksimulator/pkg/httpx => ../httpx
	github.com/owaspattacksimulator/pkg/store => ../store
)
