// radius go file. 
package main // what should we name it?

import (
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"

)

// parameter db: the sql database of all mobile users' information within our network
func start_radius_server(db *sql.DB) {
	// define handler
	// handler query through the databse and if the imsi provided 
	// from the user is not found, send reject code 
	// accept code instead otherwise
	handler := func(w radius.ResponseWriter, r *radius.Request) {
		// grabbing information
		// note that we assume username = imsi
		// optional ip is undefined
		username := rfc2865.UserName_GetString(r.Packet)
		// password := rfc2865.UserPassword_GetString(r.Packet)
		var code radius.Code
		_, err := db.Query("SELECT *  FROM customers WHERE customers.imsi = ?", username)
		if err != nil {
			log.WithError(err).Error("Cannot find this customer in our db")
			code = radius.CodeAccessReject
		} else {
			code = radius.CodeAccessAccept
		}

	    //code = radius.CodeAccessAccept
	    //code = radius.CodeAccessReject

	    log.Printf("Writing %v to %v", code, r.RemoteAddr)	
		w.Write(r.Response(code))
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


