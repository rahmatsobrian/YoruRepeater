package apbringer

import (
	"errors"
	"strings"

	"yoru.dev/yorud/internal/netinfo"
	"yoru.dev/yorud/internal/safeexec"
)

// PickDownstream decides which interface Yoru should host the AP on, given the
// capability set and the user's wish. Returning "" means "nothing usable".
//
// Preference: an explicitly configured name (if it exists and is wireless),
// then an idle secondary radio, then an existing AP interface, then a
// framework-managed AP interface.
func PickDownstream(dev *netinfo.Device, want string, allowReclaim bool) (iface string, why string) {
	links, err := dev.Links()
	if err != nil {
		return "", "interfaces could not be read"
	}
	byName := map[string]netinfo.Link{}
	for _, l := range links {
		byName[l.Name] = l
	}
	if want != "" && want != "auto" {
		l, ok := byName[want]
		if !ok {
			return "", "the configured downstream interface " + want + " does not exist"
		}
		if !l.Wireless && netinfo.Classify(l) != netinfo.ClassWiFiAP {
			return "", want + " is not a Wi-Fi interface"
		}
		return want, "explicitly configured"
	}
	var ap, idle, second []string
	for _, l := range links {
		if !l.Wireless && netinfo.Classify(l) != netinfo.ClassWiFiAP {
			continue
		}
		switch netinfo.Classify(l) {
		case netinfo.ClassWiFiAP:
			ap = append(ap, l.Name)
		case netinfo.ClassWiFiP2P:
			continue
		default:
			if !l.Up || !l.Running {
				idle = append(idle, l.Name)
			} else {
				second = append(second, l.Name)
			}
		}
	}
	if len(ap) > 0 {
		return ap[0], "reusing the access-point interface the system already exposes"
	}
	if len(idle) > 0 && allowReclaim {
		return idle[0], "claimed an idle secondary Wi-Fi interface for hostapd"
	}
	if len(second) > 0 {
		return "", "every Wi-Fi interface is already associated as a client and cannot be reused without disconnecting you; enable a second radio or use the framework hotspot"
	}
	return "", "no Wi-Fi interface is available to act as an access point"
}

// PickUpstream chooses the interface traffic should leave through.
func PickUpstream(dev *netinfo.Device, want string) (iface string, why string, err error) {
	if want != "" && want != "auto" {
		if !safeexec.ValidIface(want) {
			return "", "", errors.New("invalid upstream interface name")
		}
		l, lerr := dev.Link(want)
		if lerr != nil {
			return "", "", lerr
		}
		addrs, _ := dev.Addrs()
		if !netinfo.IsUsableUpstream(l, addrs) {
			return want, "using " + want + " as instructed although it has no usable address yet", nil
		}
		return want, "explicitly configured", nil
	}
	l, lerr := dev.DefaultUpstream()
	if lerr != nil {
		return "", "", lerr
	}
	return l.Name, "interface holding the default route", nil
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}
