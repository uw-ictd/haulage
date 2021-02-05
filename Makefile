# Git VCS parameters
VERSION=$(shell git describe --tags)
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

build_arm64:
	# A complex build line is required since gopacket uses the shared libpcap C library.
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CGO_LDFLAGS="-L/usr/lib/aarch64-linux-gnu/" CC="aarch64-linux-gnu-gcc" $(GOBUILD) -o $(BINARY_LOCATION)-arm64 -v

build-clean:
	$(GOCLEAN)

package: build
	$(info $$VERSION is [${VERSION}])
	$(info $$USER_EMAIL is [${USER_EMAIL}])
	fpm --input-type dir \
		--output-type deb \
		--force \
		--config-files $(CONF_LOCATION) \
		--after-install ./init/postinst \
		--after-remove ./init/postrm \
		--license MPL-2.0 \
		--vendor uw-ictd \
		--maintainer matt9j@cs.washington.edu \
		--description $(DESCRIPTION) \
		--url "https://github.com/uw-ictd/haulage" \
		--deb-build-depends libpcap-dev \
		--deb-compression gz \
		--name haulage \
		--version $(VERSION) \
		--depends 'libpcap0.8, default-mysql-server, default-mysql-client, python3, python3-yaml, python3-mysqldb' \
		./init/haulage.service=/lib/systemd/system/haulage.service \
		./init/haulagedb.py=/usr/bin/haulagedb \
		./haulage.sql=/tmp/haulage_sampledb.sql \
		$(BINARY_LOCATION)=/usr/bin/ \
		$(CONF_LOCATION)=/etc/haulage/

package-clean:
	rm haulage_*\.deb

quickstart_ubuntu:
	wget https://dl.google.com/go/go1.14.linux-amd64.tar.gz
	sudo tar -C /usr/local -xzf go1.14.linux-amd64.tar.gz
	rm -rf go1.14.linux-amd64.tar.gz
	sudo apt-get -y install libpcap-dev ruby ruby-dev rubygems
	sudo gem install --no-ri --no-rdoc fpm
	echo 'PATH=$$PATH:/usr/local/go/bin' >> ~/.profile

clean: package-clean build-clean
