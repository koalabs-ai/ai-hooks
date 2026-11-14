VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed "s/^v//" || echo 0.1.0-dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
export CGO_ENABLED = 0

.PHONY: build test vet cross checksums latency selftest demo clean set-module release docs

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ai-hooks ./cmd/ai-hooks

test: vet
	go test ./...

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l .; echo "gofmt needed"; exit 1)

selftest: build
	./dist/ai-hooks test

# static binaries for linux/darwin x amd64/arm64
cross:
	@for os in linux darwin; do for arch in amd64 arm64; do \
	  echo "build $$os/$$arch"; \
	  GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ai-hooks-$$os-$$arch ./cmd/ai-hooks || exit 1; \
	done; done

checksums: cross
	cd dist && sha256sum ai-hooks-* > SHA256SUMS

# cold-start latency of the three hot paths (needs hyperfine-free shell loop)
latency: build
	@scripts/latency.sh dist/ai-hooks

demo: build
	demo/build.sh

# rewrite the Go module path, e.g. make set-module MODULE=github.com/acme/ai-hooks
set-module:
	@test -n "$(MODULE)" || (echo "usage: make set-module MODULE=github.com/<org>/ai-hooks"; exit 1)
	@scripts/set-module.sh $(MODULE)

# reproducible release archives, checksums.txt and an SBOM in dist/release (usage: make release VERSION=0.1.0)
release:
	scripts/release.sh $(VERSION)

docs: build
	scripts/gen-docs.sh dist/ai-hooks

clean:
	rm -rf dist
