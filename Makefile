# Git VCS parameters
VERSION=$(shell git describe)
USER_EMAIL=$(shell git config --get user.email)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
BINARY_LOCATION=./haulage
CONF_LOCATION=./config.yml
DESCRIPTION="haulage: a minimalist traffic logging framework"

all: build package

build:
	$(GOBUILD) -o $(BINARY_LOCATION) -v

build-clean:
	$(GOCLEAN)

package: build
	$(info $$VERSION is [${VERSION}])
	$(info $$USER_EMAIL is [${USER_EMAIL}])
	fpm --input-type dir \
		--output-type deb \
		--force \
		--config-files $(CONF_LOCATION) \
		--license MPL-2.0 \
		--vendor uw-ictd \
		--maintainer matt9j@cs.washington.edu \
		--description $(DESCRIPTION) \
		--url "https://github.com/uw-ictd/haulage" \
		--deb-compression gz \
		--deb-systemd ./init/haulage.service \
		--deb-systemd-restart-after-upgrade \
		--name haulage \
		--version $(VERSION) \
		--depends 'libpcap0.8' \
		$(BINARY_LOCATION)=/usr/bin/ \
		$(CONF_LOCATION)=/etc/haulage/

package-clean:
	rm haulage_*\.deb

clean: package-clean build-clean
