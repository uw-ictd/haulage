# Git VCS parameters
VERSION=$(shell git describe --tags)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test

TARGET_DIR=./build

.PHONY: all build package quickstart_ubuntu build_arm64 build-clean clean

all: build package

build:
	$(GOBUILD) -o $(TARGET_DIR)/haulage -v

build_arm64:
	# A complex build line is required since gopacket uses the shared libpcap C library.
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CGO_LDFLAGS="-L/usr/lib/aarch64-linux-gnu/" CC="aarch64-linux-gnu-gcc" $(GOBUILD) -o $(TARGET_DIR)/haulage -v

build-clean:
	$(GOCLEAN)

package: export VERSION := $(VERSION)
package: build
	$(info $$VERSION is [${VERSION}])
	cat nfpm.yaml | \
	TARGET_ARCHITECTURE=amd64 envsubst '$${TARGET_ARCHITECTURE}' | \
	nfpm pkg --packager deb --config /dev/stdin --target $(TARGET_DIR)

package-clean:
	rm $(TARGET_DIR)/haulage_*\.deb

quickstart_ubuntu:
	wget https://dl.google.com/go/go1.14.linux-amd64.tar.gz
	sudo tar -C /usr/local -xzf go1.14.linux-amd64.tar.gz
	rm -rf go1.14.linux-amd64.tar.gz
	sudo apt-get -y install libpcap-dev
	echo 'PATH=$$PATH:/usr/local/go/bin' >> ~/.profile

clean: package-clean build-clean
