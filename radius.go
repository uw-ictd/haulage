// radius go file. 
package main // what should we name it?

import (
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"net"
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"

)

// bugs: placeholders for the sql lib


// confusions:
// q1: is that possible for an imsi that does not have an ip?
// q2: what should we set the secret


// parameter db: the sql database of all mobile users' information within our network
func start_radius_server(db *sql.DB) {
	// define handler
	// handler query through the databse and if the imsi provided 
	// from the user is not found, send reject code 
	// accept code instead otherwise
	handler := func(w radius.ResponseWriter, r *radius.Request) {
		log.Printf("We have one Request")
		// grabbing information
		// note that we assume username = imsi
		// optional ip is undefined
		imsi := rfc2865.UserName_GetString(r.Packet)
		log.Printf("The imsi is " + imsi)
		// query through database to find if this imsi matches some IP
		// if it does, write back the IP
		// Reject otherwise
		// QueryString := "SELECT ip FROM static_ips WHERE imsi = " + imsi
		rows, err := db.Query("SELECT ip FROM static_ips WHERE imsi = ?", imsi)
		defer rows.Close()
		var res *radius.Packet = radius.New(radius.CodeAccessAccept, r.Secret)
	    res.Authenticator = r.Authenticator
		if err != nil {
			// sth wrong with our database 
			log.WithError(err).Error("We cannot query through our databse")
			// what should we behave here? reject the user? or should we just return?
		    res.Code = radius.CodeAccessReject // what should we set the secret?
		} 
		//else {
			// we should accept the user
			// res = radius.New(radius.CodeAccessAccept, []byte(`res`)) // what should we set the secret?
		//}	
		
		// grab the IP if existed
		var ip string
		if rows.Next() {
			if err1 := rows.Scan(&ip); err1 != nil {
				log.Fatal("sql.rows.Scan() does not work")
		    	res.Code = radius.CodeAccessReject // what should we set the secret?
			} else {
				// we have found the ip
				res.Code = radius.CodeAccessAccept
				log.Printf("The IP we found for imsi: %s is IP: %s", imsi, ip)
				// transform ip from string to IPv4 form
				IP_found := net.ParseIP(ip)
				// add the ip to FramedIPAddress attribute of our packet
				err2 := rfc2865.FramedIPAddress_Add(res, IP_found)
				if (err2 != nil) {
					log.Fatal("Cannot add the ip to the packet")
					// we should handle this situation
					// what to send back then?
		    		res.Code = radius.CodeAccessReject // what should we set the secret?
				}
			}
		} else {
			// could be sql's problem or we cannot find an ip mapped to this given imsi
			log.WithError(err).Error("sql.Rows.Next() cannot prepare next row or we cannot find ip mapped to the given imsi from user")
			 res.Code = radius.CodeAccessReject
		}

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

	log.Printf("Starting server on :1812")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

