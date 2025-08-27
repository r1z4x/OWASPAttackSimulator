module github.com/owaspattacksimulator/internal/attack

go 1.23

require (
	github.com/owaspattacksimulator/internal/common v0.0.0
	github.com/owaspattacksimulator/internal/httpx v0.0.0
	github.com/owaspattacksimulator/internal/mutate v0.0.0
)

replace (
	github.com/owaspattacksimulator/internal/common => ../common
	github.com/owaspattacksimulator/internal/httpx => ../httpx
	github.com/owaspattacksimulator/internal/mutate => ../mutate
)