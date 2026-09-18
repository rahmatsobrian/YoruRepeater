// Command probe is a development tool: it dumps parsed netlink/sysfs state so
// the readers can be validated against a real kernel during development.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"yoru.dev/yorud/internal/caps"
	"yoru.dev/yorud/internal/logging"
	"yoru.dev/yorud/internal/netinfo"
	"yoru.dev/yorud/internal/sysinfo"
)

func main() {
	var section string
	flag.StringVar(&section, "section", "net", "net | caps | battery | thermal | cpu | mem | storage")
	flag.Parse()
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	log := logging.New(logging.Options{Level: logging.Warn, RingSize: 50})
	dev := netinfo.NewDevice()
	switch section {
	case "net":
		_ = enc.Encode(dev.Snapshot(true))
	case "caps":
		lvl := logging.Debug
		if os.Getenv("YORU_QUIET") != "" {
			lvl = logging.Error
		}
		log = logging.New(logging.Options{Level: lvl, Stderr: true, RingSize: 400})
		c := caps.NewSet(log, dev, os.Getenv("YORU_MODPATH"))
		c.Probe()
		_ = enc.Encode(map[string]any{"capabilities": c.All(), "summary": c.Summarise()})
	case "battery":
		_ = enc.Encode(sysinfo.ReadBattery())
	case "thermal":
		_ = enc.Encode(map[string]any{"zones": sysinfo.Thermals(), "hwmon": sysinfo.HwmonSensors()})
	case "cpu":
		s := sysinfo.NewCPUSampler()
		sample := s.Sample()
		for i := 0; i < 30; i++ {
			time.Sleep(100 * time.Millisecond)
			sample = s.Sample()
		}
		_ = enc.Encode(sample)
	case "mem":
		_ = enc.Encode(map[string]any{"mem": sysinfo.Memory(), "swaps": sysinfo.Swaps(), "procs": sysinfo.Procs(), "psi": sysinfo.PSI()})
	case "storage":
		_ = enc.Encode(sysinfo.Storage())
	default:
		fmt.Fprintln(os.Stderr, "unknown section")
		os.Exit(2)
	}
}
