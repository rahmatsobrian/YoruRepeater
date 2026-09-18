# Security

The dashboard is a network-facing service reachable by every client on the AP,
so it is treated as untrusted input at every layer.

## Authentication and sessions

- Read-only monitoring is open by default; privileged operations require auth
  when a password is configured.
- Passwords are stored only as a PBKDF2 salted hash in
  `/data/adb/yoru-repeater/config/config.json` (mode `0700`). The plaintext is
  never written to disk or logs.
- The credential can only be changed through `POST /api/v1/password`, never
  through the generic config patch endpoint — this prevents a privileged
  caller from being downgraded and stops the hash from being read back.
- Sessions use server-side random tokens with an expiry (default 12h) and are
  verified in constant time. Tokens are never placed in URLs.
- Failed logins are rate limited per source.

## Command execution

There is no shell. The daemon spawns processes through a single allowlisted
executor that enforces:

- a fixed set of absolute binary paths per logical tool,
- a per-binary subcommand allowlist,
- argument shape and count bounds (only validated interface names, ports and
  numeric values chosen by the engine),
- hard timeouts with process-group kill,
- bounded output capture,
- a scrubbed environment.

No HTTP handler can reach this executor with free-form user text. There is no
`/exec`, `/shell`, `/run` or `/eval` route; requests to those paths return 404.

## API hardening

- Request bodies are size-bounded (oversized payloads get `413`) and JSON
  parsing is strict.
- Every configuration patch is validated and clamped before it is applied;
  malformed values are corrected with a logged note instead of crashing the
  daemon or rebooting the network.
- Static assets are served from an embedded filesystem: there is no web root on
  disk, and path traversal cannot escape the bundle.
- No endpoint offers arbitrary file read or write. Config is modified only
  through typed, validated fields.
- Privileged routes (repeater start/stop/restart, config, password, client
  clear) are gated behind the same session policy as reads when auth is on.
- Rate limiting is applied per source for both login and privileged writes.

## Firewall safety

Yoru creates rules only in its own chains/comments and removes only those. It
never flushes tables, never rewrites global policy, and never removes VPN or
tethering rules. Cleanup runs on stop, on uninstall and from a backup copy of
the binary so it can complete even after the module directory is gone.

## Secrets hygiene

- Wi-Fi passphrases and the dashboard password are never logged and never
  returned by any API.
- Log redaction strips credential-like values before they reach disk.
- Diagnostics output is scrubbed: it reports tools, interfaces and capabilities,
  never secrets.
- The log page in the UI highlights errors but cannot expose tokens.

## Network exposure

- DHCP and DNS bind the downstream address only, never all interfaces, so the
  phone does not become an open resolver for the upstream network.
- The dashboard binds the LAN address first and loopback last; `bind` is
  configurable (`lan`, `loopback`) and port is validated.
- Log rotation bounds on-disk growth so a verbose device cannot fill `/data`.

## Reporting

If you believe you have found a vulnerability, please open an issue with
reproduction steps and the output of `yoructl diagnose` **with secrets removed**.
Do not attach `config.json`; it may contain password material.
