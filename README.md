# Caduceus

Caduceus is the public Rust appliance-control lever for sovereign HOMESERVER devices.

It gives users a safe local command surface for public device management while the private land organs stay sealed away:

- Fulcrum, Azoth, Kether, Cibation, and Paligenesis remain private.
- Harmonia performs declared profile convergence.
- Caduceus routes public appliance intent and writes public-safe receipts.
- Arcadia and future front ends may call Caduceus instead of duplicating actuator code.

## Command surface

Core:

```text
caduceus help
caduceus identity show
caduceus profile show
caduceus health
caduceus serve
```

Sync, update, receipts, staff, network, PJLink, and profile-specific routes are
declared per appliance in `profiles/<name>/index.yaml`. Run `caduceus help` on
device for the full list allowed on that body.

### Cert band (Hestia Anchor household TLS)

HomeServer mints TLS leaves under one household root CA; Console, TV, and other
clients install the exported CA bundle once. **Full public documentation:**
[`src/bands/cert/README.md`](src/bands/cert/README.md).

HomeServer:

```text
caduceus cert status
caduceus cert issue-leaf [identity] [--sans h1,h2] [--ips a,b] [--dry-run]
caduceus cert bundle create [platform] [--dry-run]
caduceus cert apply <portal> <upstream> <certificate> <key> [--dry-run]
caduceus cert portal-admit <portal> <lan-ip> <upstream> [--aliases a,b] [--dry-run]
```

HomeConsole / HomeTV:

```text
caduceus cert status
caduceus cert trust-install <bundle> [--platform linux] [--dry-run]
```

## HTTP (LAN-open, profile-gated)

Default bind: `CADUCEUS_BIND=0.0.0.0:8787`

Core:

```text
GET /health
GET /api/v1/identity
GET /api/v1/profile
GET /api/v1/health
```

Cert band (see band README for body schemas and profile matrix):

```text
GET  /api/v1/cert/status
POST /api/v1/cert/issue-leaf
POST /api/v1/cert/bundle
POST /api/v1/cert/bundle/create
POST /api/v1/cert/apply
POST /api/v1/cert/trust-install
POST /api/v1/cert/portal-admit
```

Additional routes (legacy sbin, sync, update, PJLink, staff, …) follow the
same pattern: profile-gated, JSON receipts, no client credentials on the wire.

## Profiles and roots

Caduceus profiles are authored as YAML: `etc/caduceus/profile.yaml` on device
roots and `profiles/<name>/index.yaml` in this repository. The `commands` list
is the authority for which CLI and HTTP routes each appliance may call.

Local profile roots default to `/etc/caduceus` and `/var/lib/caduceus`. For
tests and development, set `CADUCEUS_ROOT` to a fixture root containing
`etc/caduceus` and `var/lib/caduceus`.

## Staff actuators (Python engines)

Privileged mutation lives in `data/staff-actuators/` — see
[`data/staff-actuators/README.md`](data/staff-actuators/README.md). The **cert**
band's Python engine is `caduceus_staff.house_ca`; operators call the Rust
membrane only.

## Legacy sbin ingestion

The first legacy ingestion tranche preserves one-off Serverbox/sbin script bodies
under `data/legacy-sbin/manifest.json` and exposes them through read-only
Caduceus list/show surfaces. Caduceus does not execute those bodies in this
tranche; conversion into typed appliance actions follows from the manifest, one
capability at a time.

New TLS work uses the **cert** band, not `sslKey.sh` / `createCertBundle.sh`
directly.

## Bands

Public command bands are listed in `src/bands/index.json`. Each band may ship a
`README.md` explaining what powers it grants — start with **cert** for household
TLS.

## Roadmap

Caduceus SHALL gain **PJLink** capability — LAN projector and display control
(power, input, status) so operator intent can reach TVs and projectors through
the public appliance lever. Primary home: `tv` profile; routes and receipts
follow the existing band + HTTP contract pattern.