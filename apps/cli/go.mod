module github.com/owaspattacksimulator/apps/cli

go 1.23

require (
	github.com/owaspattacksimulator/pkg/broker v0.0.0
	github.com/owaspattacksimulator/pkg/scenario v0.0.0
	github.com/owaspattacksimulator/pkg/engine v0.0.0
	github.com/owaspattacksimulator/pkg/store v0.0.0
	github.com/owaspattacksimulator/pkg/report v0.0.0
	github.com/owaspattacksimulator/pkg/common v0.0.0
	github.com/spf13/cobra v1.9.1
	github.com/fatih/color v1.16.0
	github.com/schollz/progressbar/v3 v3.14.2
	google.golang.org/grpc v1.64.0
	google.golang.org/protobuf v1.36.6
	gopkg.in/yaml.v2 v2.4.0
)

replace (
	github.com/owaspattacksimulator/pkg/broker => ../../pkg/broker
	github.com/owaspattacksimulator/pkg/scenario => ../../pkg/scenario
	github.com/owaspattacksimulator/pkg/engine => ../../pkg/engine
	github.com/owaspattacksimulator/pkg/store => ../../pkg/store
	github.com/owaspattacksimulator/pkg/report => ../../pkg/report
	github.com/owaspattacksimulator/pkg/common => ../../pkg/common
)
