package main

import (
	"database/sql"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"net"

	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"
)

func start_radius_server(db *sql.DB) {
	// handler for responding client's reqeust for IP
	handler := func(w radius.ResponseWriter, r *radius.Request) {
		log.Info("We have one Request")
		// grab imsi from username field
		// optional ip is undefined
		imsi := rfc2865.UserName_GetString(r.Packet)
		log.Info("The imsi is " + imsi)
		// find corresponding IP and return it
		// reject if unfound
		rows, err := db.Query("SELECT ip FROM static_ips WHERE imsi = ?", imsi)
		defer rows.Close()
		var res *radius.Packet = radius.New(radius.CodeAccessAccept, r.Secret)
		res.Authenticator = r.Authenticator
		// internal error
		if err != nil {
			log.WithError(err).Error("We cannot query through our databse")
			res.Code = radius.CodeAccessReject
		}
		var ip string
		if rows.Next() {
			if err1 := rows.Scan(&ip); err1 != nil {
				log.Fatal("sql.rows.Scan() does not work")
				res.Code = radius.CodeAccessReject
			} else {
				// found the ip
				res.Code = radius.CodeAccessAccept
				log.Info("The IP we found for imsi: " + imsi + " is IP: " + ip)
				// transform ip from string to IPv4 form
				IP_found := net.ParseIP(ip)
				// add the ip to FramedIPAddress attribute of the packet
				err2 := rfc2865.FramedIPAddress_Add(res, IP_found)
				// internal error
				if err2 != nil {
					log.Fatal("Cannot add the ip to the packet")
					res.Code = radius.CodeAccessReject
				}
			}
		} else {
			// sql's problem or we cannot find an ip mapped to this given imsi
			log.WithError(err).Error("sql.Rows.Next() cannot prepare next row or we cannot find ip mapped to the given imsi from user")
			res.Code = radius.CodeAccessReject
		}
		// write back to client
		err = w.Write(res)
		if err != nil {
			log.Fatal("Cannot write back the message")
			return
		}
	}

	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(handler),
		SecretSource: radius.StaticSecretSource([]byte(`secret`)),
	}

	log.Info("Starting server on: 1812")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
