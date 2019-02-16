// client-side test
// RADIUS SERVER TEST
// Chenyang Fang
package main

import (
	"context"
	"log"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	// "net"
	"fmt"
)

func main() {
	fmt.Printf("test start ... \n")
	packet := radius.New(radius.CodeAccessRequest, []byte(`secret`))
    rfc2865.UserName_SetString(packet, "208920100001105")
//	rfc2865.UserName_SetString(packet, "1234")
	rfc2865.UserPassword_SetString(packet, "Kurtis")
	response, err := radius.Exchange(context.Background(), packet, "localhost:1812")
	if err != nil {
		log.Fatal(err)
	}
	
    log.Println("Code:", response.Code)
	// var ip_found net.IP
	ip_found := rfc2865.FramedIPAddress_Get(response)
	log.Println("IP:", ip_found.String())
}

























