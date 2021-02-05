# Git VCS parameters
VERSION=$(shell git describe --tags)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test

# NFPM parameters
NFPM_VERSION = 2.2.3
BUILD_ARCH=$(shell uname -m)
ifeq ($(BUILD_ARCH),aarch64)
	NFPM_ARCH=arm64
else ifeq ($(BUILD_ARCH),x86_64)
	NFPM_ARCH=x86_64
else
	$(error Unsupported build platform architecture $(BUILD_ARCH))
endif

TARGET_DIR=./build

.PHONY: all build package quickstart_ubuntu build_arm64 build-clean clean get_nfpm package-clean

all: build package

build:
	$(GOBUILD) -o $(TARGET_DIR)/haulage -v

build_arm64:
	# A complex build line is required since gopacket uses the shared libpcap C library.
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CGO_LDFLAGS="-L/usr/lib/aarch64-linux-gnu/" CC="aarch64-linux-gnu-gcc" $(GOBUILD) -o $(TARGET_DIR)/haulage -v

build-clean:
	$(GOCLEAN)

package: export VERSION := $(VERSION)
package: build get_nfpm
	$(info $$VERSION is [${VERSION}])
	cat nfpm.yaml | \
	TARGET_ARCHITECTURE=amd64 envsubst '$${TARGET_ARCHITECTURE}' | \
	$(TARGET_DIR)/nfpm/nfpm pkg --packager deb --config /dev/stdin --target $(TARGET_DIR)

package-clean:
	rm -f $(TARGET_DIR)/haulage_*\.deb

clean: package-clean build-clean

dist-clean: clean
	rm -rf $(TARGET_DIR)

# Helper rules for installing build dependencies and tooling.
quickstart_ubuntu:
	wget https://dl.google.com/go/go1.14.linux-amd64.tar.gz
	sudo tar -C /usr/local -xzf go1.14.linux-amd64.tar.gz
	rm -rf go1.14.linux-amd64.tar.gz
	sudo apt-get -y install libpcap-dev
	echo 'PATH=$$PATH:/usr/local/go/bin' >> ~/.profile

get_nfpm: $(TARGET_DIR)/nfpm/nfpm

$(TARGET_DIR)/nfpm/nfpm:
	mkdir -p $(@D)
	curl -L https://github.com/goreleaser/nfpm/releases/download/v$(NFPM_VERSION)/nfpm_$(NFPM_VERSION)_Linux_$(NFPM_ARCH).tar.gz | tar -xz --directory "$(TARGET_DIR)/nfpm"
