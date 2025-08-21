module github.com/owaspchecker/pkg/broker

go 1.23

require (
	github.com/owaspchecker/pkg/common v0.0.0
	google.golang.org/grpc v1.62.1
	google.golang.org/protobuf v1.33.0
)

replace github.com/owaspchecker/pkg/common => ../common
