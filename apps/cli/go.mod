module github.com/owaspchecker/apps/cli

go 1.23

require (
	github.com/owaspchecker/pkg/broker v0.0.0
	github.com/owaspchecker/pkg/scenario v0.0.0
	github.com/owaspchecker/pkg/engine v0.0.0
	github.com/owaspchecker/pkg/store v0.0.0
	github.com/owaspchecker/pkg/report v0.0.0
	github.com/owaspchecker/pkg/common v0.0.0
	github.com/spf13/cobra v1.9.1
)

replace (
	github.com/owaspchecker/pkg/broker => ../../pkg/broker
	github.com/owaspchecker/pkg/scenario => ../../pkg/scenario
	github.com/owaspchecker/pkg/engine => ../../pkg/engine
	github.com/owaspchecker/pkg/store => ../../pkg/store
	github.com/owaspchecker/pkg/report => ../../pkg/report
	github.com/owaspchecker/pkg/common => ../../pkg/common
)
