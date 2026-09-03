package relayserver_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/tmc/go-iroh/relayserver"
)

func ExampleNewWithOptions() {
	// Override the default per-client receive rate when hosting the relay.
	srv := httptest.NewServer(relayserver.NewWithOptions(relayserver.WithClientRate(8 << 20)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println(resp.StatusCode)

	// Output:
	// 404
}
