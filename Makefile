define GO
//+build ignore

package main

import (
	"fmt"

	"github.com/miekg/pcap"
)

func main() {
	fmt.Println(pcap.GoVersion)
}
endef
$(file > version_release.go,$(GO))
VERSION:=$(shell go run version_release.go)
TAG="v$(VERSION)"

all:
	@echo "use \'make release\' to release $(VERSION)"
	rm -f version_release.go

.PHONY: test
test:
	@echo "TAG" $(TAG)
	@echo "VERSION" $(VERSION)
	rm -f version_release.go

.PHONY: release
release: commit push
	rm -f version_release.go
	@echo "released $(VERSION)"

.PHONY: commit
commit:
	@echo committing release $(VERSION)
	git commit -am"Release $(VERSION)"
	git tag $(TAG)

.PHONY: push
push:
	@echo pushing $(VERSION) to GitHub
	git push --tags
	git push
