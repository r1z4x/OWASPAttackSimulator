module github.com/owaspattacksimulator/internal/report

go 1.23

require (
	github.com/owaspattacksimulator/internal/common v0.0.0
	github.com/owaspattacksimulator/internal/store v0.0.0
)

replace (
	github.com/owaspattacksimulator/internal/common => ../common
	github.com/owaspattacksimulator/internal/store => ../store
)