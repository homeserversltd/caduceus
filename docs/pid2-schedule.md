# PID-2 schedule

Register this envelope with `caduceus schedule register` on standard input, or the administrative `POST /api/v1/pid2/schedule/register` door. Registration alone does not run a sync.

```json
{
  "schema": "caduceus.pid2.schedule.v1",
  "intent_id": "homeserver-nas-sync",
  "transition": "register",
  "version": "1.0.0",
  "timestamp": "2026-10-31T00:00:00Z",
  "schedule": {
    "schedule_id": "nas-sync",
    "calendar": {"frequency": "daily", "time": "02:00", "weekday": null},
    "job": {"band": "storage/backup/nas-sync", "action": "sync", "max_seconds": 21600},
    "needs": [
      {"routine_id": "nas", "line": "nas-attached"},
      {"routine_id": "nas-backup", "line": "backup-attached"}
    ]
  }
}
```

PID-2 keeps the next calendar deadline as a single clock wake and runs missed slots once on restart. A fire waits on no polling loop: it records a refusal if a required line is not Done or its routine is held, otherwise crosses the staff with the last-good baseline and retains only the deed. Coronatio's sync-now and job-status actions map to the current fire; schedule and schedule-update map to the registration and its next fire. The owner must explicitly enable a schedule after the NAS role swap disables it.
