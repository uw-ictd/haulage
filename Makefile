# Git VCS parameters
VERSION=$(shell git describe --tags | sed s/-g/+g/g)

# NFPM parameters
NFPM_VERSION = 2.5.1
# This uses the somewhat confusing but standardized GNU architecture naming
# scheme to be consistent with Debian (which can handle the complex case of
# building compilers for different architectures). Build refers to the
# architecure of the platform doing this build. Host refers to the architecture
# we are building the binary to run on. Target refers to the architecture that
# built binary emits, if it's a compiler.
BUILD_ARCH=$(shell uname -m)
ifeq ($(BUILD_ARCH),aarch64)
	NFPM_ARCH=arm64
else ifeq ($(BUILD_ARCH),x86_64)
	NFPM_ARCH=x86_64
else
	$(error Unsupported build platform architecture $(BUILD_ARCH))
endif

TARGET_DIR=./target

.PHONY: all build package \
build_arm64 build_x86_64 build-clean \
package_arm64 package_x86_64 package-clean \
clean dist-clean quickstart_ubuntu get_nfpm

all: build package

# Define the basic build and package targets for the native build architecture.
ifeq ($(BUILD_ARCH),aarch64)
build: build_arm64
package: package_arm64
else ifeq ($(BUILD_ARCH),x86_64)
build: build_x86_64
package: package_x86_64
else
	$(error Unsupported build platform architecture $(BUILD_ARCH))
endif

build_arm64:
	LIBSYSTEMD_LDFLAGS="-L/usr/lib/aarch64-linux-gnu/libsystemd.so" cargo build --release --target=aarch64-unknown-linux-gnu

build_x86_64:
	LIBSYSTEMD_LDFLAGS="-L/usr/lib/x86_64-linux-gnu/libsystemd.so" cargo build --release --target=x86_64-unknown-linux-gnu

build-clean:
	cargo clean

package_arm64: export HOST_ARCHITECTURE=aarch64-unknown-linux-gnu
package_arm64: export DEB_ARCHITECTURE=arm64
package_arm64: build_arm64 get_nfpm

package_x86_64: export HOST_ARCHITECTURE=x86_64-unknown-linux-gnu
package_x86_64: export DEB_ARCHITECTURE=amd64
package_x86_64: build_x86_64 get_nfpm

package_arm64 package_x86_64: export VERSION := $(VERSION)
package_arm64 package_x86_64:
	$(info $$VERSION is [${VERSION}])
	cat nfpm.yaml | \
	envsubst '$${HOST_ARCHITECTURE} $${DEB_ARCHITECTURE}' | \
	$(TARGET_DIR)/nfpm/nfpm pkg --packager deb --config /dev/stdin --target $(TARGET_DIR)

package-clean:
	rm -f $(TARGET_DIR)/haulage_*\.deb

clean: package-clean build-clean

dist-clean: clean
	rm -rf $(TARGET_DIR)

# Helper rules for installing build dependencies and tooling.
quickstart_ubuntu:
	wget https://sh.rustup.rs
	sh sh.rustup.rs -y
	sudo apt-get -y install libsystemd-dev
	echo 'PATH=$$PATH:/usr/local/go/bin' >> ~/.profile

get_nfpm: $(TARGET_DIR)/nfpm/nfpm

$(TARGET_DIR)/nfpm/nfpm:
	mkdir -p $(@D)
	curl -L https://github.com/goreleaser/nfpm/releases/download/v$(NFPM_VERSION)/nfpm_$(NFPM_VERSION)_Linux_$(NFPM_ARCH).tar.gz | tar -xz --directory "$(TARGET_DIR)/nfpm"
