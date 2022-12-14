# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get


PREFIX?="/"
PID_DIR = $(PREFIX)"/var/run/"
BINARY_NAME=crowdsec-custom-bouncer

#Current versioning information from env
BUILD_VERSION?="$(shell git describe --tags)"
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
BUILD_TAG="$(shell git rev-parse HEAD)"
export LD_OPTS=-ldflags "-s -w -X github.com/crowdsecurity/cs-custom-bouncer/pkg/version.Version=$(BUILD_VERSION) \
-X github.com/crowdsecurity/cs-custom-bouncer/pkg/version.BuildDate=$(BUILD_TIMESTAMP) \
-X github.com/crowdsecurity/cs-custom-bouncer/pkg/version.Tag=$(BUILD_TAG)"

RELDIR = "crowdsec-custom-bouncer-${BUILD_VERSION}"

PYTHON=python3
PIP=pip

all: clean test build

static: clean
	$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v -a -tags netgo -ldflags '-w -extldflags "-static"'

build: clean
	$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v

test:
	@$(GOTEST) -v ./...

clean:
	@rm -f $(BINARY_NAME)
	@rm -rf ${RELDIR}
	@rm -f crowdsec-custom-bouncer.tgz || ""

.PHONY: release
release: build
	@if [ -z ${BUILD_VERSION} ] ; then BUILD_VERSION="local" ; fi
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, clean" ;  exit 1 ; fi
	@echo Building Release to dir $(RELDIR)
	@mkdir $(RELDIR)/
	@cp $(BINARY_NAME) $(RELDIR)/
	@cp -R ./config $(RELDIR)/
	@cp ./scripts/install.sh $(RELDIR)/
	@cp ./scripts/uninstall.sh $(RELDIR)/
	@cp ./scripts/upgrade.sh $(RELDIR)/
	@chmod +x $(RELDIR)/install.sh
	@chmod +x $(RELDIR)/uninstall.sh
	@chmod +x $(RELDIR)/upgrade.sh
	@tar cvzf crowdsec-custom-bouncer.tgz $(RELDIR)

.PHONY: func-tests
func-tests: build
	( \
	$(PYTHON) -m venv tests/venv ; \
	./tests/venv/bin/$(PIP) install -r tests/requirements.txt ; \
	sudo tests/venv/bin/$(PYTHON) -B -m unittest -v ; \
	)
