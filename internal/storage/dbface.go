package storage

import (
    _ "github.com/go-sql-driver/mysql"
    "database/sql"
    "github.com/google/gopacket"
    "github.com/shopspring/decimal"
    log "github.com/sirupsen/logrus"
    "net"
    "errors"
)

type UseEvent struct {
    userAddress gopacket.Endpoint
    bytesUp int64
    bytesDown int64
}

type UserStatus struct {
    userAddress gopacket.Endpoint
    dataBalance int64
    currencyBalance decimal.Decimal
}

func LogUsage(db *sql.DB, event UseEvent) (UserStatus, error) {
    // TODO(matt9j) Validate what actually happens when an address can't be parsed. Is a zero address returned? Do we panic?
    ip := net.ParseIP(event.userAddress.String())
    if ip == nil {
        log.WithField("Endpoint", event.userAddress).Error("Unable to parse user IP")
    }

    // Attempt to commit an update 3 times, barring other more serious errors.
    for i := 0; i < 3; i++ {
        trx, err := db.Begin()
        if err != nil {
            log.WithField("UseEvent", event).WithError(err).Error("Unable to begin transaction")
            return UserStatus{}, err
        }

        var imsi int64
        err = trx.QueryRow("select imsi from static_ips where ip=?", ip.String()).Scan(&imsi)
        if err != nil {
            log.WithField("ip", ip).WithError(err).Error("Unable to lookup imsi's static ip address")
            // TODO(matt9j) Consider deferring the rollback?
            trx.Rollback()
            return UserStatus{}, err
        }

        var (
            rawDown     int64
            rawUp       int64
            dataBalance int64
            balance     decimal.Decimal
            bridged     bool
            enabled     bool
        )

        err = trx.QueryRow(
            "SELECT raw_down, raw_up, data_balance, balance, bridged, enabled FROM customers WHERE imsi=? ",
            imsi).Scan(&rawDown, &rawUp, &dataBalance, &balance, &bridged, &enabled)
        if err != nil {
            log.WithField("imsi", imsi).WithError(err).Error("Unable to lookup customer data")
            trx.Rollback()
            return UserStatus{}, err
        }

        // Business logic accounting for the event.
        rawDown += event.bytesDown
        rawUp += event.bytesUp
        dataBalance -= (event.bytesUp + event.bytesDown)

        _, err = trx.Exec(
            "UPDATE customers SET rawDown=?, raw_up=?, data_balance=?, enabled=?, bridged=? WHERE imsi=?",
            rawDown, rawUp, dataBalance, enabled, bridged, imsi)
        if err != nil {
            log.WithField("imsi", imsi).WithError(err).Error("Unable to execute update customer data")
            trx.Rollback()
            return UserStatus{}, err
        }

        err = trx.Commit()
        if err != nil {
            log.WithField("Attempt", i).WithField("imsi", imsi).WithError(err).Warn("Unable to commit")
        } else {
            return UserStatus{event.userAddress, dataBalance, balance}, err
        }
    }
    log.WithField("User", event.userAddress).Error("Giving up committing billing update!")
    return UserStatus{}, errors.New("data loss: unable to commit")
}
