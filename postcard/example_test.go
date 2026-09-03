package postcard_test

import (
	"fmt"

	"github.com/tmc/go-iroh/postcard"
)

func Example() {
	type message struct {
		Unsigned uint8
		Signed   int8
		Text     string
	}
	in := message{Unsigned: 200, Signed: -1, Text: "hello"}
	b, err := postcard.Marshal(in)
	if err != nil {
		panic(err)
	}
	var out message
	if err := postcard.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	fmt.Println(out, b[:2])
	// Output: {200 -1 hello} [200 255]
}
