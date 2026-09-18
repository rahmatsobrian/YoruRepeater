package repeater

import (
	"context"
	"time"
)

// contextTimeout returns a cancellable context bounded by d.
func contextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
