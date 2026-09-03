package key_test

import (
	"fmt"

	"github.com/tmc/go-iroh/key"
)

func ExampleSecretKey_Sign() {
	secret, err := key.GenerateSecretKey()
	if err != nil {
		panic(err)
	}
	message := []byte("hello")
	signature := secret.Sign(message)
	fmt.Println(secret.Public().Verify(message, signature) == nil)
	// Output: true
}
