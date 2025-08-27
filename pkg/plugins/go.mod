module github.com/owaspattacksimulator/pkg/plugins

go 1.23

require (
	github.com/owaspattacksimulator/pkg/common v0.0.0
	github.com/owaspattacksimulator/pkg/scenario v0.0.0
)

replace (
	github.com/owaspattacksimulator/pkg/common => ../common
	github.com/owaspattacksimulator/pkg/scenario => ../scenario
)
