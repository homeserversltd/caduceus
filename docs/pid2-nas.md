# PID-2 NAS routines

The primary routine observes the vault mount, the labelled primary block device and its LUKS type before crossing the staff to attach it. The mount is the attachment truth; the folders crossing seats the NAS layout, and only then are the registered NAS services released. The backup routine independently observes the vault and the labelled LUKS backup device, and attaches it when present without holding the primary routine.

The NAS role-swap chord holds both routines before its staff stages and releases them last in its finalizers. A hold lasts for this boot, stops the routine's programs and prevents its lines from being walked; release clears the runtime lines so that the world is observed again. Registrations and their complete envelopes remain in Caduceus SQLite.

```json
{"schema":"caduceus.pid2.routine.v1","intent_id":"homeserver-nas","transition":"enable","version":"1.0.0","timestamp":"2026-10-30T00:00:00Z","routine":{"routine_id":"nas","stages":[
   {"line":"vault-opened","needs":[{"kind":"await-mount","path":"/vault"}]},
   {"line":"drive-detected","needs":[{"kind":"await-line","line":"vault-opened","value":"true"},{"kind":"await-device","properties":{"SUBSYSTEM":"block","ID_PART_ENTRY_NAME":"homeserver-primary-nas"}}]},
   {"line":"nas-formatted","needs":[{"kind":"await-line","line":"drive-detected","value":"true"},{"kind":"await-device","properties":{"SUBSYSTEM":"block","ID_PART_ENTRY_NAME":"homeserver-primary-nas","ID_FS_TYPE":"crypto_LUKS"}}]},
   {"line":"nas-attached","needs":[{"kind":"await-line","line":"nas-formatted","value":"true"}],"do":[{"staff":"storage/nas/attach","payload":{"role":"primary"},"deadline_seconds":180}],"until":[{"kind":"await-mount","path":"/mnt/nas"}]},
   {"line":"folders-seated","needs":[{"kind":"await-line","line":"nas-attached","value":"true"}],"do":[{"staff":"storage/nas/folders","payload":{"role":"primary"},"deadline_seconds":180}]},
   {"line":"services-released","needs":[{"kind":"await-line","line":"folders-seated","value":"true"}],"actions":[{"unit":"jellyfin.service"},{"unit":"navidrome.service"},{"unit":"filebrowser.service"},{"unit":"calibre-web.service"},{"unit":"calibre-simple-watch.service"},{"unit":"transmissionVPN.service"}]}
  ]}}
```

```json
{"schema":"caduceus.pid2.routine.v1","intent_id":"homeserver-nas-backup","transition":"enable","version":"1.0.0","timestamp":"2026-10-30T00:00:00Z","routine":{"routine_id":"nas-backup","stages":[
   {"line":"vault-opened","needs":[{"kind":"await-mount","path":"/vault"}]},
   {"line":"backup-detected","needs":[{"kind":"await-line","line":"vault-opened","value":"true"},{"kind":"await-device","properties":{"SUBSYSTEM":"block","ID_PART_ENTRY_NAME":"homeserver-backup-nas","ID_FS_TYPE":"crypto_LUKS"}}]},
   {"line":"backup-attached","needs":[{"kind":"await-line","line":"backup-detected","value":"true"}],"do":[{"staff":"storage/nas/attach","payload":{"role":"backup"},"deadline_seconds":180}],"until":[{"kind":"await-mount","path":"/mnt/nas_backup"}]}
  ]}}
```
