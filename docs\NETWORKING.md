# Networking

Yoru shares an upstream link over Wi-Fi AP using NAT. Mode selection is driven
by capability probes at runtime; nothing about interface names, firewall
backends or available tools is assumed.

## Modes

| Mode | Upstream | Downstream | Requirement |
|------|----------|------------|-------------|
| A — True repeater | Wi-Fi STA | Wi-Fi AP | Driver supports concurrent STA + AP |
| B — Hotspot router | Mobile data / any iface | Wi-Fi AP | AP capability + NAT backend |
| C — USB router | USB network (`usb0`, `rndis0`) | Wi-Fi AP | USB tethering active |
| D — Ethernet router | `eth0` | Wi-Fi AP | Ethernet present |

Upstream detection prefers an interface with a default route and working
internet, and reports the choice plus the reason. VPN interfaces (`tun0`,
`wg0`) are reported but never hijacked as upstream.

## Defaults

```text
Gateway      192.168.50.1
DHCP pool    192.168.50.10 - 192.168.50.200
DNS          the AP gateway, forwarding upstream
Lease        1h (renew 1/2, rebind 7/8)
WebUI        http://192.168.50.1:8080
```

The subnet is configurable. Yoru refuses to enable an AP whose subnet overlaps
the upstream network, because that configuration cannot route.

## Interface discovery

Interfaces are enumerated from `/sys/class/net` and netlink rather than by name
guessing, so `wlan0` / `wlan1` / `ap0` / `swlan0` / `SoftAp0` / `rmnet_data0` /
`ccmni0` / `usb0` / `eth0` are all recognised — as is anything else the vendor
invents. Each candidate is classified by capability:

- has a default route likely internet reachable
- supports AP mode (driver/phy attribute + `iw` info when available)
- currently associated as a station
- virtual (bridge, VLAN, VPN tunnel)

## NAT and routing

IPv4 forwarding is enabled for the session, and a MASQUERADE/equivalent rule is
installed for the downstream subnet. Ownership rules:

- Rules are created in Yoru-owned chains/comments (e.g. `YORU_REPEATER`) and
  only those are removed on stop/uninstall.
- The daemon **never** runs `iptables -F`, `-t nat -F` or `nft flush ruleset`.
  Flushing would destroy the user's existing VPN, tethering and firewall state.
- `nftables` is preferred where available; `iptables-nft` and legacy variants
  are both probed.
- IPv6 is never disabled globally. Where prefix delegation is unavailable, IPv6
  is reported as unavailable rather than broken.

On failure the engine rolls back: addresses, routes, rules and hostapd state are
reverted before an error is surfaced, so a failed start never leaves the device
without networking.

## DHCP and DNS

Yoru ships its own DHCP server (UDP/67) and DNS forwarder; both bind only the
downstream address, never `0.0.0.0`, so they cannot become an open resolver on
the upstream network. Bindings, hostname, lease time and per-client traffic come
from this server, which is why the Clients page is accurate even without
`dnsmasq`.

DNS answers are forwarded upstream with bounded cache and concurrency. Lease
file scanning (`/data/misc/dhcp`, vendor paths) is used as a secondary source
when another server is authoritative.

## Clients

Clients are correlated from DHCP leases, ARP/neighbour tables and per-Client
traffic counters. Reported per client where available: hostname, MAC (full or
masked), IPv4/IPv6, connection duration, RX/TX bytes and packets, and signal
information when the driver exposes it.

## Diagnostics

`yoructl diagnose` (or `GET /api/v1/diagnostics`) reports the resolved mode,
upstream choice, discovered interfaces, NAT backend, DHCP/DNS state, the
capability matrix and every missing tool with the paths that were probed. It
never includes secrets.
