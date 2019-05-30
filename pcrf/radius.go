package main

import (
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"encoding/binary"

	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"
)

func start_radius_server() {	
	
	handler := func(w radius.ResponseWriter, r *radius.Request) {
		// grab user info 
		user := rfc2865.UserName_GetString(r.Packet)
		dataBytes := rfc2865.State_Get(r.Packet);
			
		localUpBytes := binary.LittleEndian.Uint64(dataBytes[0:8])
		localDownBytes := binary.LittleEndian.Uint64(dataBytes[8:16])
		extUpBytes := binary.LittleEndian.Uint64(dataBytes[16:24])
		extDownBytes := binary.LittleEndian.Uint64(dataBytes[24:32])	

		LogUserPeriodic(user, int64(localUpBytes), int64(localDownBytes), int64(extUpBytes),  int64(extDownBytes))
			
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
