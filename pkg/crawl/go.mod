module github.com/owaspchecker/pkg/crawl

go 1.23

require (
	github.com/owaspchecker/pkg/common v0.0.0
	github.com/gocolly/colly/v2 v2.2.0
)

replace github.com/owaspchecker/pkg/common => ../common
