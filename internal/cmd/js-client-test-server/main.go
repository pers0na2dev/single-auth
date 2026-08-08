// Command js-client-test-server runs an ephemeral native Go auth server for
// the isolated clients/ Bun integration suite.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	singleauth "github.com/pers0na2dev/single-auth"
)

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	baseURL := "http://" + listener.Addr().String()
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: baseURL,
		Secret:  "single-auth-js-client-test-secret",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(baseURL)
	server := &http.Server{Handler: auth}
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
