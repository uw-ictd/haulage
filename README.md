# haulage
A golang tool for measuring, logging, and controlling network usage to allow billing and analysis.

>haul·age
>
>/ˈhôlij/ noun
>
>the commercial transport of goods,
>a charge for commercial transport of goods
>
> *-definition from google.com*

## When haulage?

* When you need to account for network traffic flows passing through a unix system.
* When you are interested in aggregate usage, not packet by packet logging or detailed timing stats.
* When you need to operate in human time (pseudo real time).
* When you operate in a constrained environment where alternative (and more fully featured) tools may be overkill.

# Usage

## Install from source with go
 1) Install the go tools for your platform, available from [golang.org](https://golang.org/doc/install)
 2) `go get github.com/uw-ictd/haulage`

## Binary releases

Forthcoming. If you're interested in helping us build a binary packaging infrastructure we would love your help!

# Developing

haulage is an open source project, and participation is always welcome. We strive to be an open and
respectful community, so please read and follow our [Community Code of Conduct](CODE_OF_CONDUCT.md).

Please feel free to open issues on github or reach out to the mailing list with any development concerns, and a
maintainer will do their best to respond in a reasonable amount of time. When proposing feature requests, keep in mind
the mission of haulage to remain a simple, customizable, and lightweight tool. Other more powerful open source network
monitoring frameworks already enjoy broad community support.

For more details check out the [contriubting](CONTRIUBTING.md) page.

# History

Haulage grew out of a need for the [CoLTE Community Cellular Networking project](https://github.com/uw-ictd/colte) to measure network utilization to
account for spending against prepaid cellular data packages and log long-term traffic statistics to aid network
planning. Many feature rich network monitors exist, but offer relatively heavy implementations over-provisioned for our
needs. The entire community networking stack is deployed on a single low-cost minicomputer, so rich toolsets designed
for a server context with relatively high idle resource consumption are not appropriate. These tools scale well, but
have made design decisions for scale at the expense of efficient performance in less demanding settings.
