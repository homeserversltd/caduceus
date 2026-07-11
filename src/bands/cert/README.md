# Cert band — Hestia Anchor household TLS

The **cert** band is Caduceus' public control surface for household TLS under
**Hestia Anchor**. HomeServer holds one stable household root CA; every service
certificate is a **leaf** signed beneath it. Console, TV, phone, and laptop
install the **same CA bundle once** per root ring — new portals add leaves, not
new trust rituals.

Doctrine: `pali:sphragis-hestia-anchor-root-ca-tablet` and sibling constellation
leaves.

## What this band grants

| Role | What you can do | What you cannot do |
|------|-----------------|-------------------|
| **HomeServer** | Mint leaves, export CA bundles, wire nginx for portals, admit portal constituents (DHCP/DNS/leaf/nginx/state) | Rotate the root CA in v1; issue certs for other households |
| **HomeConsole / HomeTV** | Install the household CA bundle; read local trust status | Issue leaves, export bundles, admit portals, change DHCP/DNS |
| **Phone / laptop** | Install the exported CA bundle (via UI or `trust-install` on Linux) | Any server-side issuance |

**Customer rule:** one CA bundle install per device per root ring. Adding a
portal or service adds a **leaf** under the same root — clients do **not**
reinstall trust.

## Architecture (two snakes)

```text
Operator / Arcadia / Coronatio
        │
        ▼
  Rust cert band (CLI + HTTP)     ← public membrane, profile-gated
        │
        ▼
  caduceus_staff.house_ca         ← privileged Python engine (OpenSSL, files, nginx, state)
```

- **Rust** (`src/bands/cert.rs`, `serve.rs`) — typed CLI and HTTP routes, JSON
  receipts, profile gate. Never holds private key bytes in public output.
- **Python** (`data/staff-actuators/caduceus_staff/house_ca.py`) — nine
  composable primitives; only `state_commit` replaces durable state.

Launcher on device: `/usr/local/sbin/caduceus-house-ca` (Harmonia ships it).

## Primitives (Python engine)

| Primitive | Purpose |
|-----------|---------|
| `ensure_root` | Converge stable household root at `/var/lib/caduceus/certs/ca.pem` (internal; never rotates existing root in v1) |
| `issue_leaf` | Mint or renew a service leaf (`{identity}.pem` + key) with DNS and IP SANs |
| `bundle_export` | Export **CA-only** bundle for a platform (no private material) |
| `trust_install` | Verify and install a CA bundle into the local trust store |
| `apply_nginx` | Stage an nginx `server` block for a portal + upstream + leaf paths |
| `constituent_lock` | Bind portal FQDN to LAN IP (DHCP/DNS adapters; v1 records plan honestly) |
| `portal_admit` | HomeServer composition: lock → leaf → nginx → state |
| `status` | Role-aware readback (root, bundle, portals, constituents) |
| `state_commit` | Atomic replace of `caduceus.household.tls.v1` in `/var/lib/caduceus/state.json` |

## CLI (profile-gated)

Commands are allowed only when listed in the appliance profile
(`profiles/<name>/index.yaml` → `commands`).

### HomeServer

```bash
caduceus cert status
caduceus cert issue-leaf [identity] [--sans h1,h2] [--ips a,b] [--dry-run]
caduceus cert bundle create [platform] [--dry-run]
caduceus cert apply <portal> <upstream> <certificate> <key> [--dry-run]
caduceus cert portal-admit <portal> <lan-ip> <upstream> [--aliases a,b] [--dry-run]
```

Platforms for `bundle create`: `linux`, `macos`, `windows`, `android`, `chromeos`.

### HomeConsole / HomeTV

```bash
caduceus cert status
caduceus cert trust-install <bundle> [--platform linux] [--dry-run]
```

`--dry-run` computes the plan and performs zero mutation on disk.

## HTTP (LAN-open, profile-gated)

Bind default: `CADUCEUS_BIND=0.0.0.0:8787` (`caduceus serve`).

| Method | Route | HomeServer | Console/TV |
|--------|-------|------------|------------|
| GET | `/api/v1/cert/status` | yes | yes |
| POST | `/api/v1/cert/issue-leaf` | yes | no |
| POST | `/api/v1/cert/bundle` | yes | no |
| POST | `/api/v1/cert/bundle/create` | yes (alias) | no |
| POST | `/api/v1/cert/apply` | yes | no |
| POST | `/api/v1/cert/trust-install` | no | yes |
| POST | `/api/v1/cert/portal-admit` | yes | no |

POST bodies accept JSON fields such as `identity`, `sans`, `ips`, `platform`,
`bundle`, `portal`, `lan_ip`, `upstream`, `aliases`, and `dry_run`. Responses
are JSON receipts with `ok`, `primitive`, `changed`, and `firstMissingSignal`.

Front ends (Arcadia, Coronatio) should call these routes instead of shelling
OpenSSL or duplicating file paths.

## Storage (defaults)

| Path | Contents |
|------|----------|
| `/var/lib/caduceus/certs/ca.pem` | Household root CA (public) |
| `/var/lib/caduceus/certs/ca.key.pem` | Root private key (HomeServer only, mode 600) |
| `/var/lib/caduceus/certs/{identity}.pem` | Service leaf certificate |
| `/var/lib/caduceus/certs/{identity}.key.pem` | Leaf private key |
| `/var/lib/caduceus/certs/bundles/` | Exported CA bundles per platform |
| `/etc/nginx/conf.d/caduceus-*.conf` | Portal proxy blocks from `apply` |
| `/var/lib/caduceus/state.json` | `caduceus.household.tls.v1` ledger |

Override roots for tests: `CADUCEUS_ROOT`, `CADUCEUS_CERT_DIR`, `CADUCEUS_STATE_PATH`.

## Typical flows

### HomeServer — new service TLS

```bash
caduceus cert issue-leaf hermes.home.arpa --sans home.arpa --ips 192.168.123.11
caduceus cert apply hermes.home.arpa http://127.0.0.1:PORT \
  /var/lib/caduceus/certs/hermes.home.arpa.pem \
  /var/lib/caduceus/certs/hermes.home.arpa.key.pem
```

### HomeServer — admit a portal constituent

```bash
caduceus cert portal-admit myapp.home.arpa 192.168.123.50 http://127.0.0.1:8080
```

Receipt names child proofs: `constituent_lock`, `issue_leaf`, `apply_nginx`,
`state_commit`.

### Any client — trust the household once

```bash
# On HomeServer first:
caduceus cert bundle create linux

# On Console, TV, or Linux workstation:
caduceus cert trust-install /path/to/homeserver-house-ca-linux.crt
```

## Receipts and safety

- Every mutation returns a JSON receipt; private keys and secret bytes never
  appear in stdout or HTTP bodies.
- `client_reinstall_required` stays `false` on leaf re-issue — the exported CA
  bundle fingerprint is stable.
- `caduceus cert rotate-ca` is **not v1**; root-ring renewal is a separate
  household ceremony.
- Legacy `sslKey.sh` and `createCertBundle.sh` remain preserved substrate; new
  work should use this band. The legacy bundle script exports the wrong material
  if pointed at a leaf instead of the CA.

## Explicit non-powers (v1)

- No satellite appliance interlink or SHA pairing ceremony.
- No HomeConsole-to-HomeTV mesh or peer actuation.
- No OAuth or capability-token ceremony for customer trust install.
- No automatic root CA rotation.
- Console and TV cannot mint, export, or admit — they are trust **clients** only.