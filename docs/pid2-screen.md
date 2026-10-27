# PID-2 screen routine

The following is a registration envelope, not a built-in routine or an installed registry file. Hand it to `caduceus enable` on standard input, or to the attended `POST /api/v1/pid2/enable` door. Registrations live in `stats.sqlite3`; the boot gate clears runtime rows when the boot ID changes.

```json
{
  "schema": "caduceus.pid2.routine.v1",
  "intent_id": "homesi-screen",
  "transition": "enable",
  "version": "1.0.0",
  "timestamp": "2026-10-27T00:00:00Z",
  "routine": {
    "routine_id": "screen",
    "stages": [
      {"line": "gpu-ready", "needs": [{"kind": "await-device", "properties": {"SUBSYSTEM": "drm"}}]},
      {"line": "display-observed", "needs": [
        {"kind": "await-line", "line": "gpu-ready", "value": "true"},
        {"kind": "observe", "observer": "drm-connector", "pattern": "*-HDMI-*"}
      ]},
      {"line": "seat-chosen", "select": {"line": "display-observed", "map": {"present": "screen", "absent": "headless"}}},
      {"line": "sway-released", "actions": [
        {"unit": "sddm.service", "when_line": "seat-chosen", "when_value": "screen"},
        {"unit": "sway-seat.service", "when_line": "seat-chosen", "when_value": "headless"}
      ]},
      {"line": "sunshine-keyed", "needs": [
        {"kind": "await-line", "line": "sway-released", "value": "true"},
        {"kind": "await-ready", "unit": "hometv-sway-session.target"}
      ], "actions": [
        {"unit": "sunshine@screen.service", "when_line": "seat-chosen", "when_value": "screen"},
        {"unit": "sunshine@headless.service", "when_line": "seat-chosen", "when_value": "headless"}
      ]}
    ]
  }
}
```

The owner Sway readiness observation is supplied by the existing owner-scoped `hometv-sway-session.target`: Sway's serialized handoff checks its IPC socket and imports its environment before starting that target. PID-2 reads the target through the sibling `unit/control` staff crossing; its `readback.active_state` is the signal. The target is observe-only in the PID-2 unit enumeration. A missing crossing or inactive target holds the line; it does not start Sunshine. The linkage between the future screen/headless units and this handoff remains a deployment boundary. This repository does not create the staff band, install either unit, or start a live body.

The PID-2 HTTP read doors are `GET /api/v1/pid2/list` and `GET /api/v1/pid2/status/<routine-or-unit>`. Mutations use `POST /api/v1/pid2/<verb>` with an Alkahest envelope; administrative admission applies. `enable` receives the routine envelope itself. For `disable`, `start`, `stop`, `restart`, and `answer`, `payload` carries the target or answer. The CLI exposes `enable`, `disable`, `start`, `stop`, `restart`, `status`, and `list` on HomeSI. A successful queue receipt is not evidence that a unit is running: readback reports the row and the separately observed staff state.
