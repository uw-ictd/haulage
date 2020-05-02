[![Go Report Card](https://goreportcard.com/badge/github.com/uw-ictd/haulage)](https://goreportcard.com/report/github.com/uw-ictd/haulage)
[![Build Status](https://travis-ci.org/uw-ictd/haulage.svg?branch=master)](https://travis-ci.org/uw-ictd/haulage)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](LICENSE)

| UPDATE: Our team recently ported EPC codebases from OAI to open5gs! Per all of our tests, this release should work well, but we encourage you to test-drive it and report any bugs - Spencer, 27 March 2020. |
| --- |

# haulage
A golang tool for measuring, logging, and controlling network usage to
allow billing and analysis.

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
## Install from source with go
 1) Install the go tools (version >= 1.11) for your platform, available from
    [golang.org](https://golang.org/doc/install)
 2) Install the libpcap library and headers (on debian flavors `apt-get install libpcap-dev`)
 3a) `go get github.com/uw-ictd/haulage`
 3b) As an alternative to (3a), clone this repo and then `make build`

## Binary releases
We currently host/maintain .deb packages for Ubuntu 18.04 and Debian 9. Use
the following script to add our repo and install haulage.
```
echo "deb http://colte.cs.washington.edu $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/colte.list
sudo wget -O /etc/apt/trusted.gpg.d/colte.gpg http://colte.cs.washington.edu/keyring.gpg
sudo apt-get update
sudo apt-get install haulage
```
### Building your own binary
 1) Download and install [fpm](https://github.com/jordansissel/fpm) for your
    platform.
 2) Build a binary package with `make package`.

## Configuration
All haulage configurations are located in config.yml. If you installed
our .deb package, this file is located in /etc/haulage.

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
Haulage grew out of a need for the [CoLTE Community Cellular
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
