package main

import (
	"database/sql"
	"net"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/gopacket"
	log "github.com/sirupsen/logrus"
	"github.com/uw-ictd/haulage/internal/iptables"
	"github.com/uw-ictd/haulage/internal/storage"
)

type Context struct {
	db           *sql.DB
	pollers      *sync.WaitGroup
	terminateSig chan struct{}
}

type Parameters struct {
	dbAddr          string
	dbUser          string
	dbPass          string
	flowLogInterval time.Duration
	userLogInterval time.Duration
	pollInterval    time.Duration
}

type CustomConfig struct {
	ReenableUserPollInterval time.Duration `yaml:"reenablePollInterval"`
	DBLocation               string        `yaml:"dbLocation"`
	DBUser                   string        `yaml:"dbUser"`
	DBPass                   string        `yaml:"dbPass"`
}

// Called on system startup.
func OnStart(ctx *Context, params Parameters) {
	dbString := params.dbUser + ":" + params.dbPass + "@/" + params.dbAddr
	log.WithField("dbString", dbString).Debug("Connecting to db")

	db, err := sql.Open("mysql", dbString)
	if err != nil {
		log.Fatal(err)
	}
	ctx.db = db

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	// Setup iptables filtering
	synchronizeFiltersToDb(db)

	// Setup a periodic poller to detect topup
	ctx.pollers = new(sync.WaitGroup)
	ctx.pollers.Add(1)
	ctx.terminateSig = make(chan struct{})
	pollInterval := params.pollInterval
	go pollForReenabledUsers(ctx.terminateSig, ctx.db, ctx.pollers, pollInterval)
}

// Cleanup can be called at any time, even on a crash.
func Cleanup(ctx *Context) {
	ctx.db.Close()
}

// Stop is called gracefully at the end of the server lifecycle.
func OnStop(ctx *Context) {
	close(ctx.terminateSig)
	ctx.pollers.Wait()
}

// The callback functions are executed periodically by the main subsystem.
func LogUserPeriodic(user gopacket.Endpoint, localUpBytes int64, localDownBytes int64, extUpBytes int64, extDownBytes int64) {
	// TODO(matt9j) Consider logging local traffic just for analysis purposes.
	// TODO(matt9j) Add this to the wait group and run db operations async.
	status, err := storage.LogUsage(ctx.db,
		storage.UseEvent{UserAddress: user, BytesUp: extUpBytes, BytesDown: extDownBytes})
	if err != nil {
		log.WithError(err).WithField("User", user).Error("Unable to log usage")
	}

	verifyBalance(status)
}

func LogFlowPeriodic(start time.Time, stop time.Time, flow gopacket.Flow, bytesAB int, bytesBA int, wg *sync.WaitGroup) {
	defer wg.Done()
	storage.LogFlow(ctx.db, start, stop, flow, "", "", bytesAB, bytesBA)
}

func verifyBalance(user storage.UserStatus) {
	// Send a single alert when crossing a threshold. Go in reverse order so that if the user crosses multiple
	// thresholds at once only the lowest alert is sent.
	switch {
	case user.CurrentDataBalance > 10000000: // 10MB
		// In the normal case when the user has lots of balance, exit early and skip the check processing below.
		return
	case (user.CurrentDataBalance <= 0) && (user.PriorDataBalance > 0):
		log.WithField("User", user.UserAddress).Info("No balance remaining")
		addr := net.ParseIP(user.UserAddress.String())
		if addr == nil {
			log.WithField("Endpoint", user.UserAddress).Error("Unable to parse an IP from endpoint")
		}
		iptables.EnableForwardingFilter(addr)
		storage.UpdateBridgedState(ctx.db, addr, false)
	case (user.CurrentDataBalance <= 1000000) && (user.PriorDataBalance > 1000000):
		log.WithField("User", user.UserAddress).Info("Less than 1MB remaining")
	case (user.CurrentDataBalance <= 5000000) && (user.PriorDataBalance > 5000000):
		log.WithField("User", user.UserAddress).Info("Less than 5MB remaining")
	case (user.CurrentDataBalance <= 10000000) && (user.PriorDataBalance > 10000000):
		log.WithField("User", user.UserAddress).Info("Less than 10MB remaining")
	}
}

func pollForReenabledUsers(terminateSignal chan struct{}, db *sql.DB, wg *sync.WaitGroup, interval time.Duration) {
	defer wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-terminateSignal:
			log.Info("Shutting down poller")
			return
		case <-ticker.C:
			usersToEnable := storage.QueryToppedUpCustomers(db)
			for _, userIp := range usersToEnable {
				log.WithField("User", userIp).Info("Re-enabling user traffic")
				iptables.DisableForwardingFilter(userIp)
				storage.UpdateBridgedState(db, userIp, true)
			}
		}
	}
}

func synchronizeFiltersToDb(db *sql.DB) {
	storedState := storage.QueryGlobalBridgedState(db)

	log.Info("----------Beginning state synchronization----------")
	for _, user := range storedState {
		log.WithField("User", user.Addr).WithField("Bridged:", user.Bridged).Info("Setting user bridging")
		if user.Bridged {
			iptables.DisableForwardingFilter(user.Addr)
		} else {
			iptables.EnableForwardingFilter(user.Addr)
		}
	}
	log.Info("----------State synchronization ended----------")
}

type UserContext struct {
	DataBalance int64
}

func (context *UserContext) Init(user gopacket.Endpoint) {
	// TODO(gh/8) Abuse the store api and store an update of 0 to get the status.
	status, err := storage.LogUsage(ctx.db,
		storage.UseEvent{UserAddress: user, BytesUp: 0, BytesDown: 0})
	if err != nil {
		log.WithField("user", user).Warn("Failed to init user")
	}

	context.DataBalance = status.CurrentDataBalance
}

func (context *UserContext) ShouldLogNow(outstandingData int64) bool {
	return outstandingData >= context.DataBalance
}
