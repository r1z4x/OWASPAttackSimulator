module github.com/owaspattacksimulator/pkg/scenario

go 1.23

require (
	github.com/owaspattacksimulator/pkg/common v0.0.0
	github.com/owaspattacksimulator/pkg/engine v0.0.0
	github.com/owaspattacksimulator/pkg/store v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace (
	github.com/owaspattacksimulator/pkg/common => ../common
	github.com/owaspattacksimulator/pkg/engine => ../engine
	github.com/owaspattacksimulator/pkg/store => ../store
)
