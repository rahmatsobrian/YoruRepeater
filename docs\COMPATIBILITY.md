# Compatibility

## Android versions

| Version | SDK  | Status |
|---------|------|--------|
| 10      | 29   | Supported |
| 11      | 30   | Supported |
| 12 / 12L| 31-32| Supported |
| 13      | 33   | Supported |
| 14      | 34   | Supported |
| 15      | 35   | Supported |
| 16      | 36   | Supported (API-level behaviour, no version-specific hacks) |
| 17      | 37+  | Expected to work; not verifiable until release |

Below SDK 29 the installer aborts: the API surface the daemon relies on
(netlink diagnostics, `cmd wifi`, thermal/power sysfs layout) is not stable
enough to promise correct monitoring.

Architecture is chosen by capability detection, not by version. Anything
version-specific lives behind a probe: if a tool or sysfs path is absent, the
feature is reported **Unsupported** rather than approximated.

## Architectures

| ABI         | Binary          | Notes |
|-------------|-----------------|-------|
| arm64-v8a   | `yorud-arm64`   | Preferred; all devices since ~2019 |
| armeabi-v7a | `yorud-arm`     | 32-bit, `GOARM=7` |

Both are built statically with `CGO_ENABLED=0`, so there is no libc dependency.
The installer picks one at flash time from `ro.product.cpu.abi` /
`abilist` / `uname -m` and aborts if neither is bundled. `x86` / `x86_64` are
not shipped: the target is real phones, and no emulator ABI is claimed as
supported.

## Root solutions

| Solution  | Install | Notes |
|-----------|---------|-------|
| Magisk    | Yes     | `service.sh` in `late_start`, `post-fs-data.sh` honoured |
| KernelSU  | Yes     | Detected via `$KSU`; same module format |
| APatch    | Yes     | Detected via `$APATCH` |

Detection is informational — the module uses only standard module entry points,
so it does not depend on which manager flashed it.

## Tooling

Nothing is assumed to exist. The daemon probes for each binary across the paths
where Android has historically placed it (`/system/bin`, `/vendor/bin`,
`/apex/...`, `/sbin`) and degrades per feature:

- `ip` — required for addressing and routes. Without it, repeater mode is
  unavailable; monitoring still works from sysfs.
- `iw` / `iwconfig` — Wi-Fi detail (frequency, RSSI, link speed). Optional.
- `iptables` (legacy or nft) / `nft` — NAT. At least one is required to share
  upstream; if neither exists the repeater is reported unavailable.
- `hostapd` — AP bring-up. Optional: Android's own tethering stack is preferred
  when present and usable.
- `dnsmasq` — optional; Yoru ships its own DHCP and DNS servers and only uses
  `dnsmasq` if the platform one is already authoritative.
- `dumpsys` / `cmd` / `settings` / `svc` — optional Android integration.
- `toybox` / `busybox` — optional convenience only; never a hard dependency.

## Hardware limitations

Wi-Fi concurrency is a driver property. Yoru probes for it and never fakes it:

| Capability | Fallback |
|------------|----------|
| Concurrent STA + AP | True repeater |
| AP only | Hotspot router (upstream via data/USB/Ethernet) |
| No AP | Reported as unsupported with the driver reason |

Other known constraints, surfaced rather than hidden:

- Some vendor drivers refuse AP while STA is associated; the UI explains this
  instead of retrying silently.
- 5/6 GHz AP support and channel selection are limited to what the driver
  advertises.
- Battery current/voltage and cycle counters vary by fuel gauge; missing
  fields are blank, not zero-filled.
- Thermal zone naming is vendor specific. Yoru maps what it recognises and
  exposes raw values separately.
- SELinux enforcing can block `chcon`; contexts are best-effort and the daemon
  runs from the root domain regardless.
