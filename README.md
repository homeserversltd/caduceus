# Caduceus

Caduceus is the public Rust appliance-control lever for sovereign HOMESERVER devices.

It gives users a safe local command surface for public device management while the private land organs stay sealed away:

- Fulcrum, Azoth, Kether, Cibation, and Paligenesis remain private.
- Harmonia performs declared profile convergence.
- Caduceus routes public appliance intent and writes public-safe receipts.
- Arcadia and future front ends may call Caduceus instead of duplicating actuator code.

Initial command surface:

```text
caduceus identity show
caduceus profile show
caduceus health
caduceus legacy-sbin list
caduceus legacy-sbin show <script-id>
caduceus sync status
caduceus sync now [--no-restart] [--dry-run]
caduceus update status
caduceus update now --dry-run
caduceus help
caduceus update service status
caduceus update service toggle on --dry-run
caduceus update service toggle off --dry-run
caduceus receipts latest
caduceus serve
```

HTTP tranche (LAN-open, profile-gated, no client credentials):

```text
GET /health
GET /api/v1/identity
GET /api/v1/profile
GET /api/v1/health
GET /api/v1/legacy-sbin
GET /api/v1/legacy-sbin/show?id=<script-id>
```

Default bind: `CADUCEUS_BIND=0.0.0.0:8787`

Local profile roots default to `/etc/caduceus` and `/var/lib/caduceus`. Caduceus profiles are authored as YAML: `etc/caduceus/profile.yaml` on device roots and `profiles/<name>/index.yaml` in this repository. Installed legacy `profile.json` remains a read-only compatibility fallback after `profile.yaml`/`profile.yml`. For tests and development, set `CADUCEUS_ROOT` to a fixture root containing `etc/caduceus` and `var/lib/caduceus`.

## Legacy sbin ingestion

The first legacy ingestion tranche preserves one-off Serverbox/sbin script bodies under `data/legacy-sbin/manifest.json` and exposes them through read-only Caduceus list/show surfaces. Caduceus does not execute those bodies in this tranche; conversion into typed appliance actions follows from the manifest, one capability at a time.

## Roadmap

Caduceus SHALL gain **PJLink** capability — LAN projector and display control (power, input, status) so operator intent can reach TVs and projectors through the public appliance lever. Primary home: `tv` profile; routes and receipts follow the existing band + HTTP contract pattern.
