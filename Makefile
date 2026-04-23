.PHONY: all clean test server harry bootstrap release

BINDIR := bin
GOFILES := $(shell find . -name '*.go' -not -path './vendor/*')
LDFLAGS_STRIP := -ldflags="-s -w"

PLATFORMS := darwin-arm64 linux-amd64 linux-arm64

all: server harry

server: $(BINDIR)/harry-server

harry: $(BINDIR)/harry

# Cross-compile stripped binaries for all platforms
bootstrap: $(foreach p,$(PLATFORMS),$(BINDIR)/harry-$(p))

release: bootstrap $(foreach p,$(PLATFORMS),$(BINDIR)/harry-server-$(p))

$(BINDIR)/harry-server: $(GOFILES)
	@mkdir -p $(BINDIR)
	go build -o $@ ./cmd/server

$(BINDIR)/harry: $(GOFILES)
	@mkdir -p $(BINDIR)
	go build -o $@ ./cmd/harry

# Client cross-compile
$(BINDIR)/harry-darwin-arm64: $(GOFILES)
	@mkdir -p $(BINDIR)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS_STRIP) -o $@ ./cmd/harry

$(BINDIR)/harry-linux-amd64: $(GOFILES)
	@mkdir -p $(BINDIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS_STRIP) -o $@ ./cmd/harry

$(BINDIR)/harry-linux-arm64: $(GOFILES)
	@mkdir -p $(BINDIR)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS_STRIP) -o $@ ./cmd/harry

# Server cross-compile
$(BINDIR)/harry-server-darwin-arm64: $(GOFILES)
	@mkdir -p $(BINDIR)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS_STRIP) -o $@ ./cmd/server

$(BINDIR)/harry-server-linux-amd64: $(GOFILES)
	@mkdir -p $(BINDIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS_STRIP) -o $@ ./cmd/server

$(BINDIR)/harry-server-linux-arm64: $(GOFILES)
	@mkdir -p $(BINDIR)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS_STRIP) -o $@ ./cmd/server

test:
	go test ./...

clean:
	rm -rf $(BINDIR)
