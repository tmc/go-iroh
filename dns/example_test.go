package dns_test

import (
	"fmt"
	"net/netip"

	"github.com/tmc/go-iroh/dns"
)

func ExampleEndpointData() {
	data := dns.NewEndpointData()
	data.AddIPAddrs(netip.MustParseAddrPort("192.0.2.1:443"))
	user, err := dns.NewUserData("device=laptop")
	if err != nil {
		panic(err)
	}
	data.SetUserData(&user)
	fmt.Println(data.IPAddrs()[0], data.UserData())
	// Output: 192.0.2.1:443 device=laptop
}
