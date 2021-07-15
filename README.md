[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](LICENSE)

| UPDATE: I've recently completed a major overhaul of haulage to better support long-term maintenance, system upgrades, and integration with other front-ends besides CoLTE. As part of this change we've re-written the haulage core in rust instead of golang, and the low-level details have changed substantially. If you're upgrading an existing system, be sure to checkout the Upgrading section below : ) -Matt J. |
|---|

# haulage
A tool for measuring, logging, and controlling network usage to allow billing
and analysis.

>haul·age
>
>/ˈhôlij/ noun
>
> 1. the act or process of hauling
> 2. a charge made for hauling
>
> *-Merriam-Webster Online*

## When haulage?
* When you need to account for network traffic flows passing through a
  unix system.
* When you are interested in aggregate usage, not packet by packet
  logging or detailed timing.
* When you need to operate in human time (pseudo real time).
* When you operate in a constrained environment where alternative (and
  more fully featured) tools may be overkill.

# Usage
## Binary releases
We currently host/maintain .deb packages for Ubuntu 18.04, Ubuntu 20.04, and
Debian 10 as part of the [CoLTE project](https://github.com/uw-ictd/colte). You
can use the following script to add the colte repo and install haulage.
```
echo "deb [signed-by=/usr/share/keyrings/colte-archive-keyring.gpg] http://colte.cs.washington.edu $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/colte.list
sudo wget -O /usr/share/keyrings/colte-archive-keyring.gpg http://colte.cs.washington.edu/colte-archive-keyring.gpg
sudo apt update
sudo apt install haulage
```
## Configuration
All haulage configurations are located in config.yml. If you installed via the
.deb package, this file is located at /etc/haulage/config.yml.

Importantly, this file determines which network interface haulage should
monitor, and haulage will fail to start if you have not set it to a valid
interface for your deployment system.

### Database
Haulage relies on a backing Postgres database to store durable state
information. The package installation scripts assume the postgresql database
server is installed with default parameters, and will create a basic empty
`haulage_db` database with a `haulage_db` user authorized for access. If your
deployment environment uses an external database, you will need to manually
configure the database parameters in the haulage config file and then run
`haulage --db-upgrade` to update the database to the required schema.

The installation script will not overwrite an existing haulage_db database to
prevent unintentional data loss, so if you remove or reinstall the package
without using apt purge, you may need to manually drop this database.

## Administration
The deb package installs a systemd service `haulage.service` but does not
automatically start or enable it on installation. If you would like to
automatically run haulage on startup, use systemctl to start and enable the
service.
```
# Starts haulage running
sudo systemctl start haulage.service
# Enables haulage to start automatically on system startup/restart
sudo systemctl enable haulage.service
```
If you are using the systemd service, logs are available in the journal, and can
be accessed with the usual journalctl commands. `sudo journalctl -u
haulage.service -f` will open a streaming view of the current log.

# Upgrading from haulage 0.0.*

Prior versions of haulage used MySQL/Mariadb instead of Postgres, with a
different database schema. The package installs a migration script which can be
manually run to migrate an existing install to the new schema.

Before running it, be sure to configure your /etc/haulage/config.yml file with
the database login credentials *for the new installation*, and make sure both
databases are up. You will specify the legacy database credentials on the
command line for the migration script.

As an example, to migrate an existing default installation
(mariadb://haulage_db:haulage_db@localhost/haulage_db) after upgrading haulage
to 0.2.*, run
```
haulage-pg-migrate -c /etc/haulage/config.yml --currency USD \
--mysql-db-name haulage_db --mysql-db-user haulage_db --mysql-db-pass haulage_db
```

This script is availabe in the source repo at if you need to customize it for
your deployment
https://github.com/uw-ictd/haulage/tree/main/python/migrate_mysql_to_pg.py

# Building from source

If you would like to build from source, you will need rust stable 1.53.0 or
newer. See
[https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)
for instructions. Once you have rust installed, you can build a debug binary for
your local architecture with cargo (`cargo build`), or a fully optimized release
binary with (`cargo build --release`). The built binaries will be availabe in
the target directory. The project uses a cargo workspace, with individual crates
in subdirectories. Checkout the root Cargo.toml file to see the specific
locations of each component.

We provide a makefile for locally building the release binary and deb packages
which can be run with `make`. This makefile has not been extensively tested
outside our own CI pipeline, so if you encounter issues please reach out!

The `pkg/crossplatform` directory also contains infrastructure for building
packages for all supported platforms in isolated docker environments. To build
binaries appropriate for all platforms, run `python3
pkg/crossplatform/build_all.py` *from the root directory of the repo*. Your
local user will need to have docker priviliges and the docker daemon will need
to be installed and running. The built packages will be available in the
``build/`` directory.

# Developing
haulage is an open source project, and participation is always
welcome. We strive to be an open and respectful community, so please
read and follow our [Community Code of Conduct](CODE_OF_CONDUCT.md).

Please feel free to open issues on github or reach out to the mailing
list with any development concerns, and a maintainer will do their
best to respond in a reasonable amount of time. When proposing feature
requests, keep in mind the mission of haulage to remain a simple,
customizable, and lightweight tool. Other more powerful open source
network monitoring frameworks already enjoy broad community support.

For more details check out the [contriubting](CONTRIUBTING.md) page.

# History
The requirements for haulage grew out of a need for the [CoLTE Community Cellular
Networking project](https://github.com/uw-ictd/colte) to measure
network utilization to account for spending against prepaid cellular
data packages and log long-term traffic statistics to aid network
planning. Many feature rich network monitors exist, but offer
relatively heavy implementations over-provisioned for our needs. The
entire community networking stack is deployed on a single low-cost
minicomputer, so rich toolsets designed for a server context with
relatively high idle resource consumption are not appropriate. These
tools scale well, but have made design decisions for scale at the
expense of efficient performance in less demanding settings.
