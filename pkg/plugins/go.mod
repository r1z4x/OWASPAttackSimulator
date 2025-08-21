module github.com/owaspchecker/pkg/plugins

go 1.23

require (
	github.com/owaspchecker/pkg/common v0.0.0
	github.com/owaspchecker/pkg/scenario v0.0.0
)

replace (
	github.com/owaspchecker/pkg/common => ../common
	github.com/owaspchecker/pkg/scenario => ../scenario
)
