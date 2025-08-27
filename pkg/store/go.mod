module github.com/owaspattacksimulator/pkg/store

go 1.23

require (
	github.com/owaspattacksimulator/pkg/common v0.0.0
	github.com/mattn/go-sqlite3 v1.14.17
)

replace github.com/owaspattacksimulator/pkg/common => ../common
