# Yoru Repeater

A rooted-Android Wi-Fi repeater / hotspot router with a real-time Material 3
web dashboard. Ships as a standard root module for **Magisk**, **KernelSU** and
**APatch**.

The phone joins an upstream network (Wi-Fi, USB or Ethernet) and shares it as a
Wi-Fi AP with NAT, DHCP and DNS, while a self-contained Go daemon serves a
dashboard to connected clients on port 8080 — no companion app, no internet, no
CDN.

## Build

Builds run **only** in GitHub Actions. Nothing is compiled on your workstation.

```text
push / PR  -> validate  fmt, vet (host + linux/arm64), tests, shell, JS, JSON, CRLF
           -> build     cross-compile arm64 + arm, assemble module zip, SHA256SUMS
tag v*     -> release   publish zip + checksums to GitHub Releases
```

Grab the zip from the **Actions** run artifact, or from **Releases** for tagged
versions. To build manually on Ubuntu 22.04/24.04 (Go >= 1.22, `zip`, `file`):

```bash
bash build.sh                  # -> dist/Yoru-Repeater-vX.X.X.zip + SHA256SUMS
VERSION=1.2.3 bash build.sh    # override the version
```

Before pushing, run the same gates CI runs:

```bash
bash tools/lint-sh.sh          # shell syntax under dash/busybox/bash
bash tools/check-web.sh        # WebUI JS syntax
```

## Install

1. Flash `Yoru-Repeater-vX.X.X.zip` in Magisk / KernelSU / APatch.
2. Reboot.
3. Open `http://<phone-ip>:8080` from any client on the AP (default subnet
   `192.168.50.0/24`, gateway `192.168.50.1`).

Requires Android 10+ (SDK 29+) and `arm64-v8a` or `armeabi-v7a`.

## Control

`yorud` and `yoructl` are on `PATH` through the module overlay:

```bash
yoructl status                 # repeater + internet + client summary
yoructl start | stop | restart
yoructl config                 # dump current configuration
yoructl config '{"web":{"port":8081}}'
yoructl diagnose               # environment / capability report
yoructl logs -n 200 -level warn -grep hostapd
```

## Dashboard

Material 3 Expressive UI with dynamic color, light / dark / AMOLED themes, and
a responsive layout (bottom nav on phones, nav rail on tablets, sidebar on
desktop). Pages: Dashboard, Repeater, Clients, Wi-Fi, Network, System, Battery,
Performance, Traffic, Logs, Settings, About.

Every value is read from the device (`/proc`, `/sys`, netlink, `dumpsys`). When
a feature is unavailable the UI says **Unsupported** with a reason rather than
fabricating a number.

## API

Read-only monitoring is open by default; privileged operations require auth.

```text
GET  /api/v1/status  health  system  cpu  memory  battery  temperature
GET  /api/v1/storage  wifi  network  clients  traffic  streams  history
GET  /api/v1/logs  config  capabilities  diagnostics  info
POST /api/v1/login  logout  password  config  clients/clear
POST /api/v1/repeater/start  /stop  /restart
```

## Configuration and state

```text
/data/adb/yoru-repeater/config/config.json    settings (0700, may hold secrets)
/data/adb/yoru-repeater/logs/                 rotating logs
/data/adb/yoru-repeater/state/                runtime state, supervisor pid
```

Config survives upgrades. `POST /api/v1/config` accepts partial patches; the
dashboard password can only be changed via `POST /api/v1/password`.

## Safety

Only Yoru-owned firewall rules (`YORU_REPEATER*`) are created, and only those
are removed on stop/uninstall — the daemon never flushes tables and never
touches VPN rules. The daemon spawns processes exclusively through an
allowlisted executor with fixed arguments, timeouts and bounded output; there is
no shell and no arbitrary-command API.

## Capability-driven operation

Wi-Fi concurrency is hardware dependent, so Yoru probes before enabling:

1. **True repeater** — concurrent STA + AP.
2. **Hotspot router** — upstream interface + NAT to the AP.
3. **USB / Ethernet router** — wired upstream.
4. Otherwise: a diagnostic error explaining exactly what is missing.

## Documentation

- `docs/COMPATIBILITY.md` — Android versions, ABIs, root solutions
- `docs/NETWORKING.md` — modes, routing, NAT, DHCP/DNS
- `docs/SECURITY.md` — threat model, auth, privilege separation
