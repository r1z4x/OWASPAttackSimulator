module github.com/owaspchecker/pkg/store

go 1.23

require (
	github.com/owaspchecker/pkg/common v0.0.0
	github.com/mattn/go-sqlite3 v1.14.17
)

replace github.com/owaspchecker/pkg/common => ../common
