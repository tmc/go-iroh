package watch_test

import (
	"context"
	"fmt"

	"github.com/tmc/go-iroh/watch"
)

func ExampleValue() {
	value := watch.NewValue("starting")
	observer := value.Watch()
	fmt.Println(observer.Current())
	value.Set("ready")
	updated, err := observer.Updated(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println(updated)
	// Output:
	// starting
	// ready
}
