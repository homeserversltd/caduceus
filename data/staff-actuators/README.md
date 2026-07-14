# Caduceus staff actuators

**Staff actuators** are the privileged Python (and selected native) engines behind
Caduceus' public Rust bands. Operators and front ends call **Caduceus** — not
these modules directly.

## Layout

| Path | Role |
|------|------|
| `caduceus_staff/house_ca.py` | Hestia Anchor household TLS primitives |
| `caduceus_staff/network/dhcp.py` | Kea DHCP readback and control |
| `caduceus_staff/household_capability/` | Household capability signing and digest-only identity binding |
| `caduceus-house-ca` | Launcher: `python -m caduceus_staff.house_ca` |
| `profile.json` | Actuator catalog (id, launcher, receipt family, notes) |

Harmonia ships actuators to `/usr/local/sbin/caduceus_staff/` on each appliance.

## Dual-snake pattern

```text
caduceus cert <verb>   →   cert.rs (Rust band)
                         →   caduceus-house-ca
                         →   caduceus_staff.house_ca (Python)
```

The Rust band is the **public membrane**: profile gate, JSON receipts, HTTP
routes. Python is the **mutation engine**: OpenSSL, filesystem, nginx staging,
trust store, atomic state.

## House CA (`house_ca`)

Nine composable primitives power the **cert** band. Full public documentation:

**[`src/bands/cert/README.md`](../../src/bands/cert/README.md)**

Do not import or shell this module from application code — use `caduceus cert`
CLI or `/api/v1/cert/*` HTTP instead.