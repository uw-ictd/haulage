package main

import (
	"io/ioutil"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var (
	ctx             Context
	snapshotLen     int32 = 1024
	promiscuous           = true
	snapshotTimeout       = 5 * time.Second
	handle          *pcap.Handle
	flowHandlers    = new(sync.Map)
	userAggregators = new(sync.Map)
)

var opts struct {
	ConfigPath string `short:"c" long:"config" description:"The path to the configuration file" required:"true" default:"/etc/haulage/config.yml"`
}

var config struct {
	FlowLogInterval time.Duration `yaml:"flowLogInterval"`
	UserLogInterval time.Duration `yaml:"userLogInterval"`
	Interface       string        `yaml:"interface"`
	Custom          CustomConfig  `yaml:"custom"`
}

func parseConfig(path string) {
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.WithField("path", path).WithError(err).Fatal("Failed to load configuration")
	}

	log.Debug("Parsing" + path)
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		log.WithError(err).Fatal("Failed to parse configuration")
	}
}

func main() {
	log.Info("Starting PCRF")

	// Setup flags
	_, err := flags.Parse(&opts)
	if err != nil {
		log.Fatal(err)
	}

	parseConfig(opts.ConfigPath)

	params := Parameters{config.Custom.DBLocation, config.Custom.DBUser, config.Custom.DBPass, config.FlowLogInterval, config.UserLogInterval, config.Custom.ReenableUserPollInterval}
	log.WithField("Parameters", config).Info("Parsed parameters")

	log.Info("Initializing context")
	OnStart(&ctx, params)

	defer Cleanup(&ctx)
	log.Info("Context initialization complete")

	start_radius_server()

	var processingGroup sync.WaitGroup

	// Setup interrupt catching to cleanup connections
	sigintChan := make(chan os.Signal, 1)
	signal.Notify(sigintChan, os.Interrupt)
	go func() {
		<-sigintChan
		handle.Close()
		OnStop(&ctx)
		<-sigintChan
		log.Fatal("Terminating Uncleanly! Connections may be orphaned.")
	}()

	processingGroup.Wait()

}
