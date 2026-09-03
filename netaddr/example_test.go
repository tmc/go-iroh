package netaddr_test

import (
	"fmt"

	"github.com/tmc/go-iroh/netaddr"
)

func ExampleParseTransportAddr() {
	addr, err := netaddr.ParseTransportAddr("2a_deadbeef")
	if err != nil {
		panic(err)
	}
	custom := addr.(netaddr.CustomAddr)
	fmt.Println(custom.ID(), custom.Data())
	// Output: 42 [222 173 190 239]
}
