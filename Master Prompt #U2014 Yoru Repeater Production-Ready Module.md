# YORU REPEATER — PRODUCTION-READY ROOT WIFI REPEATER + REAL-TIME SYSTEM MONITORING

You are a senior Android/Linux networking engineer, Android root/module developer, embedded Linux developer, security engineer, and Material Design 3 frontend engineer.

Your task is to DESIGN AND IMPLEMENT a complete, production-ready Android root module called:

**Yoru Repeater**

The module must work with:

- Magisk
- KernelSU
- APatch

Target Android versions:

- Android 10
- Android 11
- Android 12
- Android 13
- Android 14
- Android 15
- Android 16
- Android 17 where technically possible

The project must NOT be a prototype, fake demo, mockup, or proof of concept.

It must be implemented as a real usable production-oriented root module.

---

# 1. PRIMARY GOAL

Create a root module that turns a rooted Android phone into a Wi-Fi repeater/router/tethering device while simultaneously providing a beautiful web-based real-time monitoring dashboard.

The rooted Android phone acts as:

```text
                 INTERNET / UPSTREAM WIFI
                         │
                         ▼
                ┌─────────────────┐
                │  Android Phone  │
                │                 │
                │  Yoru Repeater  │
                │                 │
                │  STA / upstream │
                │       +         │
                │  AP / hotspot   │
                │       +         │
                │  NAT / routing  │
                │       +         │
                │  monitoring     │
                │       +         │
                │  Web dashboard  │
                └────────┬────────┘
                         │
                   Wi-Fi AP
                         │
             ┌───────────┼───────────┐
             ▼           ▼           ▼
          Phone       Laptop       Tablet
```

Clients connected to the repeater must be able to open the dashboard from their browser without installing any application.

Example:

```text
http://192.168.x.1:8080
```

The exact address must be dynamically detected and displayed.

---

# 2. ABSOLUTE REQUIREMENTS

DO NOT:

- create only a UI mockup
- create fake statistics
- hardcode CPU/RAM/battery values
- assume one Android version
- assume one Wi-Fi interface name
- assume wlan0 always exists
- assume iptables always exists
- assume nftables always exists
- assume busybox exists
- assume Toybox behaves identically across Android versions
- require a companion Android application
- require Google Play Services
- require internet access for the dashboard
- require external CDN resources
- use fake repeater functionality
- silently ignore unsupported hardware
- silently fail when a feature is unavailable

Every displayed statistic must come from the actual device whenever possible.

When hardware/driver/kernel limitations prevent a feature, clearly report:

```text
Unsupported
```

or:

```text
Unavailable on this device
```

instead of generating fake data.

---

# 3. ROOT MODULE COMPATIBILITY

The module must be installable as a normal root module.

Support:

```text
Magisk
KernelSU
APatch
```

Use standard module mechanisms where possible.

The module must:

- install cleanly
- uninstall cleanly
- survive reboot
- start automatically after boot
- stop cleanly
- avoid bootloops
- avoid modifying system partitions unnecessarily
- avoid replacing system binaries unnecessarily
- avoid dangerous global modifications
- detect Android version
- detect root environment
- detect architecture
- detect available networking tools

Architecture support should include:

```text
arm64-v8a
armeabi-v7a
```

where technically practical.

Do not assume every device is arm64.

---

# 4. ANDROID VERSION COMPATIBILITY

Implement compatibility logic for:

```text
Android 10
Android 11
Android 12
Android 13
Android 14
Android 15
Android 16
Android 17
```

Detect:

```text
ro.build.version.sdk
ro.build.version.release
ro.product.cpu.abi
ro.product.board
ro.hardware
ro.boot.hardware
```

Do not use version-specific behavior unless necessary.

Create a compatibility abstraction layer.

For example:

```text
compat/
    android10.sh
    android11.sh
    android12.sh
    android13.sh
    android14.sh
    android15.sh
    android16.sh
    android17.sh
```

Only create files where actually useful. Avoid unnecessary duplication.

---

# 5. WIFI REPEATER / NETWORK ENGINE

Implement a real networking engine.

The system should support, depending on device capabilities:

### Mode A — Wi-Fi repeater

```text
Wi-Fi STA
     +
Wi-Fi AP
```

### Mode B — Wi-Fi hotspot/router

```text
Upstream interface
       ↓
Android
       ↓
NAT
       ↓
Wi-Fi AP
```

### Mode C — USB upstream

If technically supported:

```text
USB network
     ↓
Android
     ↓
Wi-Fi AP
```

### Mode D — Ethernet upstream

If the device exposes Ethernet networking:

```text
Ethernet
   ↓
Android
   ↓
Wi-Fi AP
```

The module must automatically detect what is possible.

---

# 6. HARDWARE / DRIVER DETECTION

Do not assume that Wi-Fi concurrency is supported.

Detect:

- Wi-Fi chipset
- interface names
- STA capability
- AP capability
- P2P capability
- concurrent STA/AP capability
- driver
- firmware
- regulatory domain where accessible
- supported frequencies
- current Wi-Fi state

Potential sources:

```text
/sys/class/net/
/sys/class/net/*/address
/sys/class/net/*/operstate
/sys/kernel/debug/
/proc/net/
/proc/net/wireless
```

and Android networking commands/APIs available through the shell environment.

Use commands such as:

```text
ip
iw
iwconfig
dumpsys wifi
cmd wifi
cmd netpolicy
cmd connectivity
```

only when available.

Detect availability before using them.

Never assume `iw`, `iwconfig`, `iptables`, `nft`, `hostapd`, or `dnsmasq` exist.

---

# 7. NETWORK INTERFACE DETECTION

Automatically discover:

```text
wlan0
wlan1
ap0
swlan0
SoftAp0
p2p0
rmnet0
rmnet_data0
ccmni0
usb0
eth0
```

and any other interfaces dynamically.

Do not hardcode one interface.

Build a network abstraction layer:

```text
NetworkManager
    ├── discoverInterfaces()
    ├── detectUpstream()
    ├── detectDownstream()
    ├── configureAP()
    ├── configureRouting()
    ├── configureNAT()
    ├── configureDNS()
    ├── getClients()
    └── getTrafficStats()
```

---

# 8. ROUTING AND NAT

Implement proper routing/NAT.

Support whichever mechanism is available:

```text
iptables
nftables
Android tethering infrastructure
```

Prefer the least invasive and most compatible method.

Never blindly flush all firewall rules.

NEVER execute dangerous commands such as:

```text
iptables -F
iptables -t nat -F
nft flush ruleset
```

because they can break the user's existing firewall/VPN/tethering configuration.

Only create Yoru-specific rules.

Use identifiable chains, for example:

```text
YORU_REPEATER
YORU_REPEATER_NAT
YORU_REPEATER_FORWARD
```

Clean up only Yoru's rules during stop/uninstall.

---

# 9. DHCP + DNS

Provide DHCP/DNS functionality using the best available Android-compatible method.

Possible implementations:

```text
dnsmasq
Android tethering DHCP
custom lightweight DHCP implementation
```

Do not blindly bundle large unnecessary binaries.

Detect existing system capabilities first.

Configure:

```text
IP address
gateway
DHCP range
DNS
lease duration
```

Example:

```text
Gateway:
192.168.50.1

DHCP:
192.168.50.10
-
192.168.50.200
```

Allow the user to configure the subnet.

Validate that the subnet does not conflict with the upstream network.

---

# 10. WIFI AP CONFIGURATION

Provide configurable:

```text
SSID
Password
Security
Channel
Band
Hidden SSID
Maximum clients
Country code
```

Support where hardware allows:

```text
2.4 GHz
5 GHz
6 GHz
```

Do not expose unsupported options.

Detect capabilities first.

Password validation must follow actual Android/hostapd requirements.

Never display Wi-Fi passwords in logs.

---

# 11. REAL-TIME CLIENT MONITORING

Display connected clients.

For every client where available:

```text
Hostname
MAC address
IPv4
IPv6
Connection duration
RX bytes
TX bytes
RX packets
TX packets
Signal information if available
```

Example:

```text
CONNECTED CLIENTS

Galaxy A12
192.168.50.10
Connected: 23 min
↓ 124 MB
↑ 42 MB

Laptop
192.168.50.11
Connected: 1h 12m
↓ 1.2 GB
↑ 238 MB
```

MAC addresses should have privacy-conscious display options.

Provide:

```text
Full MAC
Masked MAC
```

---

# 12. TRAFFIC MONITORING

Provide:

```text
Current download speed
Current upload speed
Total download
Total upload
Packets
Errors
Dropped packets
```

Show:

```text
KB/s
MB/s
GB/s
```

depending on magnitude.

Calculate rates from actual interface counters.

Do not fake traffic.

Use:

```text
/sys/class/net/<interface>/statistics/
```

where applicable.

Track:

```text
rx_bytes
tx_bytes
rx_packets
tx_packets
rx_errors
tx_errors
rx_dropped
tx_dropped
```

---

# 13. DEVICE SYSTEM MONITORING

Dashboard must provide real device statistics.

## CPU

Display:

```text
CPU usage
CPU frequency
CPU governor
CPU cores
per-core usage
per-core frequency
load average
```

Read from actual system sources.

Support heterogeneous CPUs where possible.

---

# 14. RAM

Display:

```text
Total
Used
Available
Cached
Buffers
Swap
ZRAM
```

Use:

```text
/proc/meminfo
```

when available.

---

# 15. BATTERY

Display:

```text
Battery percentage
Charging state
Battery health
Battery temperature
Battery voltage
Battery current
Battery power
Charge/discharge rate
Cycle count where available
```

Read from:

```text
/sys/class/power_supply/
```

Handle devices where filenames differ.

Do not assume:

```text
/sys/class/power_supply/battery/
```

always exists.

Automatically discover battery power supply.

---

# 16. TEMPERATURE

Discover thermal zones dynamically.

Display:

```text
CPU
GPU
Battery
PMIC
Skin
Modem
Wi-Fi
```

where identifiable.

Do not display meaningless:

```text
thermal_zone0
thermal_zone1
```

without trying to identify them.

Provide an advanced thermal-zone page for raw values.

---

# 17. STORAGE

Display:

```text
Internal storage
Used
Free
Total
```

Optionally:

```text
/data
/cache
/system
/vendor
```

when readable.

Do not scan the entire filesystem every second.

Use efficient filesystem statistics.

---

# 18. NETWORK SYSTEM INFORMATION

Display:

```text
Upstream interface
Downstream interface
Local IP
Gateway
DNS
IPv4
IPv6
MAC
Link speed
Wi-Fi RSSI
Wi-Fi frequency
Wi-Fi channel
```

where available.

---

# 19. WEB SERVER

Implement a lightweight embedded web server.

It must:

- require no external internet
- start automatically
- bind to the repeater interface
- serve static files
- provide REST API
- optionally support WebSocket/SSE
- use minimal RAM
- use minimal CPU

Preferred architecture:

```text
Web Browser
     │
     ├── REST API
     │
     └── WebSocket/SSE
            │
            ▼
      Yoru API Server
            │
            ▼
       Yoru Daemon
            │
     ┌──────┴──────┐
     ▼             ▼
 Android sysfs   Network
```

Do not require Node.js, Python, Java, or a large runtime on the Android device unless absolutely necessary.

Prefer a self-contained native/static binary.

---

# 20. API

Create a clean API.

Example:

```text
GET /api/v1/status
GET /api/v1/system
GET /api/v1/cpu
GET /api/v1/memory
GET /api/v1/battery
GET /api/v1/temperature
GET /api/v1/storage
GET /api/v1/wifi
GET /api/v1/network
GET /api/v1/clients
GET /api/v1/traffic
GET /api/v1/config
GET /api/v1/health
```

Commands:

```text
POST /api/v1/repeater/start
POST /api/v1/repeater/stop
POST /api/v1/repeater/restart
POST /api/v1/config
```

Privileged operations must require authentication.

Read-only monitoring may optionally be available without authentication depending on configuration.

---

# 21. REAL-TIME DASHBOARD

Build a complete Material Design 3 web dashboard.

The UI must NOT look like a generic Bootstrap dashboard.

Use:

**Material 3**
**Material 3 Expressive**
**Dynamic Color**
**Material You**

Design language should feel like a modern Android 14/15/16 system application translated into WebUI.

---

# 22. DYNAMIC COLOR

Implement a proper Material 3 dynamic color system.

The UI must support:

```text
Primary
On Primary
Primary Container
On Primary Container

Secondary
On Secondary
Secondary Container
On Secondary Container

Tertiary
On Tertiary
Tertiary Container
On Tertiary Container

Surface
Surface Container
Surface Container High
Surface Container Highest

Outline
Outline Variant

Error
```

Generate CSS custom properties from the active dynamic palette.

Provide multiple ways to choose color:

```text
Dynamic
System
Preset
Custom
```

If browser/system dynamic color is unavailable, gracefully fall back to a local default palette.

---

# 23. AMOLED THEME

Implement true AMOLED dark mode.

Modes:

```text
System
Light
Dark
AMOLED
```

AMOLED mode should use near-black/black surfaces where appropriate:

```text
#000000
```

while preserving Material 3 contrast.

Do not simply invert colors.

---

# 24. LIGHT THEME

Light theme must be fully designed separately.

Do not create light mode by merely changing background from black to white.

Ensure:

- proper contrast
- readable text
- correct containers
- accessible cards
- proper dividers
- readable charts
- proper disabled states

---

# 25. SYSTEM THEME

When set to:

```text
System
```

detect:

```text
prefers-color-scheme
```

and automatically switch between light and dark.

---

# 26. MATERIAL 3 EXPRESSIVE UI

Use expressive Material 3 design principles.

Include:

- large rounded cards
- expressive typography
- dynamic shapes
- prominent hero statistics
- segmented controls
- chips
- navigation rail/sidebar where appropriate
- bottom navigation on mobile
- floating action buttons where useful
- animated state changes
- smooth transitions
- responsive layouts
- large touch targets

Avoid excessive animations.

Animations must respect:

```text
prefers-reduced-motion
```

---

# 27. RESPONSIVE DESIGN

The WebUI must work perfectly on:

```text
Android phone
Android tablet
Laptop
Desktop
```

Breakpoints must adapt dynamically.

Mobile:

```text
Bottom navigation
Single-column cards
Compact charts
```

Tablet:

```text
Navigation rail
2-column layout
```

Desktop:

```text
Sidebar
Multi-column dashboard
```

---

# 28. DASHBOARD PAGES

Implement at minimum:

```text
Dashboard
Repeater
Clients
Wi-Fi
Network
System
Battery
Performance
Traffic
Logs
Settings
About
```

---

# 29. DASHBOARD HOME

Show:

```text
Repeater status
Internet status
Battery
CPU
RAM
Temperature
Wi-Fi signal
Download speed
Upload speed
Connected clients
```

Use beautiful large Material 3 cards.

Example:

```text
┌──────────────────────────────┐
│ Yoru Repeater                │
│ ● Running                    │
│                              │
│ Internet                     │
│ Connected                    │
│                              │
│ ↓ 12.4 MB/s   ↑ 2.1 MB/s     │
└──────────────────────────────┘
```

---

# 30. REPEATER PAGE

Show:

```text
Repeater state
Upstream SSID
Upstream signal
Upstream interface
Downstream AP
SSID
Channel
Band
IP
Gateway
DNS
```

Controls:

```text
Start
Stop
Restart
```

---

# 31. CLIENT PAGE

Beautiful client cards.

Each client:

```text
Device icon
Hostname
IP
MAC
Connection duration
Download
Upload
```

Add:

```text
Search
Sort
Filter
```

---

# 32. WIFI PAGE

Show:

```text
SSID
BSSID
Band
Channel
Frequency
RSSI
Link speed
Noise if available
Interface
Driver
```

Provide signal graph.

---

# 33. NETWORK PAGE

Show:

```text
Upstream
Downstream
Routing
NAT
DNS
DHCP
IPv4
IPv6
```

Show network health.

---

# 34. PERFORMANCE PAGE

Create real-time charts:

```text
CPU usage
RAM usage
Temperature
Network throughput
Battery drain/charge
```

Charts must use real values.

Use lightweight SVG/Canvas implementation.

Do not use huge chart libraries unless necessary.

---

# 35. LOG PAGE

Display Yoru logs.

Features:

```text
Live logs
Search
Filter
Error highlighting
Copy
Clear
Download
```

Log levels:

```text
DEBUG
INFO
WARN
ERROR
```

Do not expose:

- Wi-Fi passwords
- authentication tokens
- private credentials

---

# 36. SETTINGS PAGE

Settings should include:

### Appearance

```text
Theme:
System
Light
Dark
AMOLED

Dynamic Color:
Enabled/Disabled

Accent
```

### Repeater

```text
SSID
Password
Band
Channel
Subnet
DHCP range
DNS
Maximum clients
```

### Monitoring

```text
Refresh interval
Chart history
Temperature update interval
Traffic update interval
```

### Security

```text
Dashboard authentication
Session timeout
Allow LAN access
```

### Advanced

```text
Debug logging
Force interface
Custom routing
Firewall behavior
```

---

# 37. CONFIGURATION

Use a robust configuration file.

Example:

```text
/data/adb/yoru-repeater/config/
```

Do not store secrets in world-readable files.

Set appropriate permissions.

Validate every configuration value.

Do not allow malformed configuration to crash the daemon.

Provide configuration migration between versions.

---

# 38. SERVICE LIFECYCLE

Implement:

```text
Boot
 ↓
Environment detection
 ↓
Wait for Android boot completion
 ↓
Wait for Wi-Fi/network availability
 ↓
Initialize Yoru
 ↓
Start monitoring daemon
 ↓
Start web server
 ↓
Start repeater if auto-start enabled
```

Do not start too early during boot.

Handle Android boot races.

Implement graceful shutdown.

---

# 39. CRASH RECOVERY

The daemon must recover from crashes.

Implement:

```text
health check
watchdog
restart policy
backoff
```

Do not create infinite aggressive restart loops.

If repeated failures occur:

```text
Disable automatic restart
Record error
Expose diagnostic information
```

---

# 40. LOGGING

Use structured logs.

Example:

```text
2026-09-15 10:20:31 [INFO] Detecting Wi-Fi interfaces
2026-09-15 10:20:31 [INFO] Upstream: wlan0
2026-09-15 10:20:32 [INFO] AP interface: wlan1
2026-09-15 10:20:32 [INFO] NAT initialized
2026-09-15 10:20:33 [INFO] DHCP initialized
2026-09-15 10:20:34 [INFO] Yoru Repeater started
```

Use log rotation.

Do not allow logs to fill `/data`.

---

# 41. PERFORMANCE REQUIREMENTS

This module is intended for low-end Android devices too.

Optimize for devices with:

```text
2 GB RAM
3 GB RAM
4 GB RAM
```

The daemon should have extremely low idle CPU usage.

Do not poll every sysfs file every 100 ms.

Use sensible intervals.

Example:

```text
CPU: 1 second
RAM: 1 second
Battery: 5 seconds
Temperature: 2 seconds
Network traffic: 1 second
Clients: 2 seconds
```

Allow configuration.

---

# 42. SECURITY

Treat the WebUI as a network-facing service.

Implement:

- input validation
- authentication
- rate limiting
- safe command execution
- command allowlists
- path traversal protection
- no arbitrary shell execution through API
- no arbitrary file read through API
- no arbitrary file write through API
- safe JSON parsing
- bounded request sizes

NEVER expose an API such as:

```text
POST /exec
{
    "command": "..."
}
```

Do not allow arbitrary shell commands from the browser.

---

# 43. PRIVILEGE SEPARATION

The system should use least privilege where practical.

Separate:

```text
web server
monitoring
network control
privileged commands
```

The web frontend should never directly execute root shell commands.

Architecture:

```text
Browser
   ↓
API
   ↓
Controlled daemon
   ↓
Validated privileged operation
```

---

# 44. CSRF / SESSION SECURITY

If authentication is enabled:

Implement secure sessions.

Do not put passwords in URLs.

Do not store credentials in localStorage when avoidable.

Use secure random session tokens.

Expire sessions.

---

# 45. OFFLINE-FIRST WEBUI

The dashboard must work completely offline.

DO NOT use:

```text
Google Fonts
CDN
Material CDN
external icon CDN
external JavaScript CDN
external CSS CDN
```

Bundle everything required.

Material Symbols/icons should be bundled locally or implemented using local SVG/icon assets.

---

# 46. NO EXTERNAL DEPENDENCY AT RUNTIME

After module installation:

```text
No npm
No node
No Python
No internet download
No package manager
```

should be required.

The module must be self-contained.

---

# 47. ICON SYSTEM

Use a local Material Symbols / Material icon implementation.

Icons should support:

```text
outlined
rounded
filled
```

where practical.

Do not load icons from the internet.

---

# 48. ACCESSIBILITY

Implement:

```text
WCAG-conscious contrast
keyboard navigation
focus indicators
ARIA labels
screen-reader-friendly controls
reduced motion
large touch targets
```

---

# 49. ERROR HANDLING

The UI must clearly explain failures.

Bad:

```text
Error 500
```

Good:

```text
Wi-Fi repeater unavailable

Your device's Wi-Fi driver does not appear to support
concurrent Wi-Fi client + access-point mode.

You can still use Yoru as a hotspot/router.
```

---

# 50. DIAGNOSTIC PAGE

Create:

```text
Diagnostics
```

with:

```text
Root implementation
Android version
SDK
Kernel version
Architecture
Wi-Fi chipset
Wi-Fi driver
Interfaces
iptables availability
nft availability
hostapd availability
dnsmasq availability
SELinux state
Network capabilities
STA/AP concurrency
```

Include:

```text
Copy diagnostic report
Download diagnostic report
```

Never include secrets.

---

# 51. COMPATIBILITY ENGINE

Create capability detection.

Example:

```text
Capability:

WIFI_STA
WIFI_AP
WIFI_STA_AP_CONCURRENT
IPTABLES
NFTABLES
DNSMASQ
HOSTAPD
IP_COMMAND
IW
ANDROID_TETHERING
WEBSOCKET
```

The UI must adapt based on capabilities.

Unsupported options should be disabled with explanations.

---

# 52. IPV6

Support IPv6 where possible.

Do not break IPv6 when configuring IPv4 NAT.

Detect:

```text
IPv6 addresses
IPv6 routes
IPv6 DNS
```

Avoid disabling IPv6 globally.

---

# 53. VPN COMPATIBILITY

Do not blindly interfere with VPNs.

Detect VPN interfaces such as:

```text
tun0
wg0
```

and report them.

If VPN routing conflicts with repeater routing, explain it.

Do not destroy existing VPN configuration.

---

# 54. FIREWALL SAFETY

Yoru must only manipulate rules it owns.

Use comments/identifiers when supported.

Example:

```text
YORU_REPEATER
```

Cleanup must only remove Yoru rules.

---

# 55. INSTALLATION EXPERIENCE

The module ZIP must install through:

```text
Magisk
KernelSU
APatch
```

Installation should display:

```text
Yoru Repeater
Version
Android version
Architecture
Detected root solution
Detected capabilities
```

Do not fail installation merely because optional functionality is unavailable.

---

# 56. UPDATE SYSTEM

Prepare the project for future versions.

Use:

```text
version
versionCode
schemaVersion
```

Implement migration support.

---

# 57. UNINSTALL

Uninstall must clean:

```text
Yoru firewall rules
Yoru processes
Yoru network interfaces/configuration
Yoru temporary files
Yoru service state
```

Do NOT delete user configuration unless explicitly requested.

Do NOT destroy unrelated network settings.

---

# 58. PROJECT STRUCTURE

Create a clean production-oriented structure.

Example:

```text
yoru-repeater/
│
├── module.prop
├── customize.sh
├── post-fs-data.sh
├── service.sh
├── uninstall.sh
│
├── daemon/
│   ├── main
│   ├── monitor
│   ├── network
│   ├── wifi
│   ├── battery
│   ├── thermal
│   ├── clients
│   └── config
│
├── server/
│   ├── api
│   ├── auth
│   └── server
│
├── web/
│   ├── index.html
│   ├── assets/
│   ├── css/
│   └── js/
│
├── config/
│   └── default.json
│
├── scripts/
│   ├── install.sh
│   ├── detect.sh
│   ├── start.sh
│   ├── stop.sh
│   ├── diagnostics.sh
│   └── cleanup.sh
│
├── docs/
│   ├── README.md
│   ├── COMPATIBILITY.md
│   ├── NETWORKING.md
│   └── SECURITY.md
│
└── build/
```

You may improve this structure if there is a technically superior architecture.

---

# 59. BUILD SYSTEM

Provide reproducible builds.

The project should be buildable on:

```text
Ubuntu 22.04
Ubuntu 24.04
```

without unnecessary dependencies.

Provide:

```text
build.sh
```

which produces:

```text
Yoru-Repeater-vX.X.X.zip
```

Also provide:

```text
SHA256
```

for the release ZIP.

---

# 60. TESTING

Create test scripts.

At minimum:

```text
test-install.sh
test-config.sh
test-network.sh
test-api.sh
test-security.sh
test-cleanup.sh
```

Test:

- missing tools
- missing interfaces
- invalid configuration
- unsupported Wi-Fi hardware
- no upstream internet
- DHCP conflict
- subnet conflict
- daemon crash
- repeated restart
- uninstall cleanup
- API authentication
- malformed API requests

---

# 61. STATIC VALIDATION

Before declaring the project complete:

Check:

```text
shell syntax
JSON validity
HTML validity
CSS validity
JavaScript syntax
permissions
module structure
architecture compatibility
```

Do not leave:

```text
TODO
FIXME
IMPLEMENT THIS
PLACEHOLDER
MOCK DATA
FAKE DATA
```

in production paths.

---

# 62. WEBUI QUALITY

The WebUI must feel like a polished Android system application.

Use:

```text
Material 3
Material 3 Expressive
Dynamic Color
Material You
```

Visual characteristics:

- modern
- clean
- premium
- rounded
- responsive
- smooth
- expressive
- AMOLED-friendly
- Android-like
- no Bootstrap appearance
- no generic admin dashboard appearance

Use appropriate elevation, containers, tonal surfaces, typography hierarchy, chips, segmented buttons, dialogs, sheets, and cards.

---

# 63. MOBILE UI

On small screens:

```text
┌──────────────────────────┐
│ Yoru Repeater        ⋮   │
├──────────────────────────┤
│                          │
│     ● Repeater Active    │
│                          │
│        87% 🔋            │
│                          │
│  CPU        RAM          │
│  37%        61%          │
│                          │
│  ↓ 12.4 MB/s             │
│  ↑ 2.1 MB/s              │
│                          │
├──────────────────────────┤
│ Home  WiFi  Clients  ⚙  │
└──────────────────────────┘
```

Use responsive navigation.

---

# 64. DESKTOP UI

On desktop:

```text
┌────────────┬─────────────────────────────────┐
│ YORU       │ Dashboard                       │
│            │                                 │
│ Dashboard  │ ┌─────┐ ┌─────┐ ┌─────┐        │
│ Repeater   │ │ CPU │ │ RAM │ │ BAT │        │
│ Clients    │ └─────┘ └─────┘ └─────┘        │
│ Wi-Fi      │                                 │
│ Network    │ ┌────────────────────────────┐  │
│ System     │ │ Network traffic chart      │  │
│ Logs       │ └────────────────────────────┘  │
│ Settings   │                                 │
└────────────┴─────────────────────────────────┘
```

---

# 65. BRANDING

Brand:

**Yoru Repeater**

Use a professional visual identity.

Do not copy another application's branding.

Create:

- Yoru logo
- favicon
- module icon
- WebUI icon
- status icons

Use local assets.

---

# 66. INFORMATION DENSITY

Do not overwhelm the user on the home screen.

Use:

```text
summary → details
```

For example:

```text
CPU 37%
```

clicking opens:

```text
CPU details
Per-core usage
Frequency
Governor
Load
Temperature
```

---

# 67. LIVE CONNECTION STATUS

Display a clear status indicator:

```text
● Online
● Connecting
● Limited
● Offline
● Error
```

The dashboard itself should detect API connectivity loss.

If daemon disconnects:

```text
Connection lost
Reconnecting...
```

Do not freeze the UI.

---

# 68. PERSISTENT SETTINGS

Settings should persist across reboot.

Validate settings before applying them.

For dangerous network changes:

```text
Preview changes
Apply
Rollback on failure
```

where practical.

---

# 69. SAFE NETWORK ROLLBACK

If applying repeater configuration fails:

```text
1. Detect failure
2. Restore previous Yoru configuration
3. Restore previous firewall rules
4. Restore previous routing
5. Log error
6. Show diagnostic information
```

Never leave the phone in a broken networking state intentionally.

---

# 70. PRODUCTION QUALITY REQUIREMENT

The final implementation must be treated as if it will be released publicly.

Prioritize:

```text
stability
compatibility
security
performance
maintainability
recoverability
UX
```

over adding unnecessary features.

---

# 71. IMPORTANT TECHNICAL RULE

Do NOT assume that a rooted Android phone can universally perform true Wi-Fi repeating.

Wi-Fi concurrency is hardware/driver dependent.

Therefore implement a capability-driven architecture:

```text
TRUE REPEATER
      ↓
if supported

otherwise

HOTSPOT + ROUTING/NAT
      ↓
if supported

otherwise

DIAGNOSTIC ERROR
```

Never fake repeater mode.

Clearly distinguish:

```text
Wi-Fi Repeater
Wi-Fi Hotspot Router
USB Router
Ethernet Router
```

---

# 72. IMPLEMENTATION PRIORITY

Implement in this order:

## Phase 1

Core module:

- module structure
- boot service
- root detection
- architecture detection
- Android version detection
- logging
- configuration
- watchdog

## Phase 2

System monitoring:

- CPU
- RAM
- battery
- temperature
- storage
- network statistics

## Phase 3

Network engine:

- interface detection
- upstream detection
- AP detection
- routing
- NAT
- DHCP
- DNS
- client detection

## Phase 4

Web server:

- API
- authentication
- WebSocket/SSE
- static asset server

## Phase 5

WebUI:

- Material 3
- Material 3 Expressive
- Dynamic Color
- light
- dark
- AMOLED
- system theme
- responsive design

## Phase 6

Advanced features:

- diagnostics
- traffic charts
- per-client statistics
- logs
- configuration
- recovery
- compatibility layer

## Phase 7

Production hardening:

- security
- testing
- cleanup
- performance
- documentation
- release ZIP
- checksum

---

# 73. DO NOT STOP AT PLANNING

Do not only provide:

```text
architecture
pseudocode
example code
UI mockup
```

Actually implement the project.

If you have access to the filesystem/repository, inspect the existing project first.

Before modifying anything:

1. inspect the repository
2. understand existing files
3. identify build system
4. identify available tools
5. identify existing architecture
6. preserve useful existing work
7. implement incrementally
8. test after each major component

Do not blindly overwrite existing files.

---

# 74. SELF-REVIEW

After implementation, perform a full review.

Check:

### Module

```text
Does it install?
Does it boot?
Does it uninstall?
Does it survive reboot?
```

### Network

```text
Does AP work?
Does upstream work?
Does NAT work?
Does DHCP work?
Does DNS work?
Can clients access internet?
```

### Monitoring

```text
Are values real?
Are values updated?
Does monitoring survive network restart?
```

### WebUI

```text
Does mobile work?
Does desktop work?
Does light work?
Does dark work?
Does AMOLED work?
Does system theme work?
Does dynamic color work?
```

### Security

```text
Can arbitrary shell commands be executed?
Can secrets leak?
Can arbitrary files be read?
Can arbitrary files be written?
```

### Compatibility

```text
Android 10
Android 11
Android 12
Android 13
Android 14
Android 15
Android 16
Android 17
```

Clearly document anything that cannot be universally supported.

---

# 75. FINAL DELIVERABLES

At the end, provide:

```text
Yoru-Repeater-vX.X.X.zip
```

plus:

```text
SHA256SUMS
README.md
COMPATIBILITY.md
NETWORKING.md
SECURITY.md
```

The final report must include:

```text
Implemented features
Supported Android versions
Supported architectures
Supported root systems
Detected limitations
Known hardware limitations
Build instructions
Installation instructions
Usage instructions
Troubleshooting
Security model
```

---

# 76. FINAL RULE

Do not claim something is supported if it has not actually been implemented and tested.

If a feature depends on hardware, kernel, vendor implementation, Android version, or Wi-Fi driver:

```text
detect → verify → enable
```

Never:

```text
assume → enable → break network
```

The final result must be a **real production-oriented Yoru Repeater root module with a polished Material 3 Expressive + Material You WebUI**, not merely a concept or visual demo.