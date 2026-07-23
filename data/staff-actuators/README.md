# Caduceus staff actuators

**Staff actuators** are the privileged Python (and selected native) engines behind
Caduceus' public Rust bands. Operators and front ends call **Caduceus** — not
these modules directly.

## Layout

| Path | Role |
|------|------|
| `caduceus_staff/house_ca.py` | Hestia Anchor household TLS primitives |
| `caduceus_staff/network/dhcp.py` | Kea DHCP readback and control |

| `caduceus-house-ca` | Launcher: `python -m caduceus_staff.house_ca` |
| `profile.json` | Actuator catalog (id, launcher, receipt family, notes) |

Harmonia ships actuators to `/usr/local/sbin/caduceus_staff/` on each appliance.

## SacredCredential (operator provisioning)

`caduceus.key` is an ordinary Keyman service credential. Its username is the
lowercase SHA-256 of the raw `/root/key/skeleton.key` bytes; its password is the
operator PIN. It is not a `caduceus_household.key`, and no household-capability
signing path exists.

As root, compute the identity and provision exactly one credential with this
paste-ready ceremony (replace `<PIN>` only):

```sh
id=$(sha256sum /root/key/skeleton.key | cut -d ' ' -f1); /vault/keyman/newkey.sh caduceus "$id" '<PIN>'
```

The root `bind` launcher reads this credential at startup through Keyman,
creates only the in-memory signer, and returns public verifier material. If the
credential is absent it returns `UNBOUND` with
`caduceus-pin-not-yet-provisioned`; the Crown projects that as “PIN not yet
provisioned.”

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