module github.com/owaspattacksimulator/internal/mutate

go 1.23

require (
	github.com/owaspattacksimulator/internal/common v0.0.0
)

replace (
	github.com/owaspattacksimulator/internal/common => ../common
)