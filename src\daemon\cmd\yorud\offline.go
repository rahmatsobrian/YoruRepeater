// Offline helpers for `yorud probe`: these run the detection engine directly so
// an operator can diagnose hardware without starting any network service.
package main

import (
	"os"

	"yoru.dev/yorud/internal/caps"
	"yoru.dev/yorud/internal/logging"
	"yoru.dev/yorud/internal/netinfo"
)

func newQuietLogger() *logging.Logger {
	return logging.New(logging.Options{
		Level: logging.Warn, RingSize: 200, Stderr: os.Getenv("YORU_VERBOSE") != "",
	})
}

func newDevice() *netinfo.Device { return netinfo.NewDevice() }

func newCapSet(log *logging.Logger, dev *netinfo.Device) *caps.Set {
	return caps.NewSet(log, dev, envOr("YORU_MODPATH", defaultModPath))
}
