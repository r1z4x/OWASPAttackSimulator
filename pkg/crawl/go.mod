module github.com/owaspattacksimulator/pkg/crawl

go 1.23

require (
	github.com/owaspattacksimulator/pkg/common v0.0.0
	github.com/gocolly/colly/v2 v2.2.0
)

replace github.com/owaspattacksimulator/pkg/common => ../common
