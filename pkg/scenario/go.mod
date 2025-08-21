module github.com/owaspchecker/pkg/scenario

go 1.23

require (
	github.com/owaspchecker/pkg/common v0.0.0
	github.com/owaspchecker/pkg/engine v0.0.0
	github.com/owaspchecker/pkg/store v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace (
	github.com/owaspchecker/pkg/common => ../common
	github.com/owaspchecker/pkg/engine => ../engine
	github.com/owaspchecker/pkg/store => ../store
)
