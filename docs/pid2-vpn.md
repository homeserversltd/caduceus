# PID-2 VPN routine

The VPN routine observes its declared units, links and files. A change runs the transmission status route, and its declared fields feed the VPN indicator. The route's freshness deadline schedules its next necessary observation.

A step's deadline bounds PID 2's wait, while a read that outlives it finishes under the leaf's own crossing lifetime and bound.

```json
{"schema":"caduceus.pid2.routine.v1","intent_id":"homeserver-vpn","transition":"enable","version":"1.0.0","timestamp":"2026-11-02T00:00:00Z","routine":{"routine_id":"vpn","stages":[
  {"line":"vpn-observed","needs":[
    {"kind":"observe-unit","unit":"transmissionVPN.service"},
    {"kind":"observe-unit","unit":"hold-port-forward@pia.service"},
    {"kind":"observe-link","netns":"vpn","link":"veth1"},
    {"kind":"observe-link","netns":"vpn","link":"tun06"},
    {"kind":"observe-link","netns":"vpn","link":"piawg"},
    {"kind":"observe-file","path":"/run/agathodaimon/transmission/pia.json"},
    {"kind":"observe-file","path":"/etc/appliance/config.json"}],
    "do":[{"route":"transmission/status","keep":["on","conditions","forwardPort","protocol","firstMissingSignal"]}]}
]}}
```
