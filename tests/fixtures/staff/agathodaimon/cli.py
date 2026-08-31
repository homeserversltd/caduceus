#!/usr/bin/env python3
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

stdin_bytes = sys.stdin.buffer.read()
try:
    envelope = json.loads(stdin_bytes)
except (json.JSONDecodeError, AttributeError):
    envelope = {}

if (len(sys.argv) >= 2 and sys.argv[1] == "network/dns") or (len(sys.argv) >= 3 and sys.argv[1:3] == ["network", "dns"]):
    payload = envelope.get("payload", {}) if isinstance(envelope, dict) else {}
    selected = payload.get("args", []) if isinstance(payload, dict) else []
    result = subprocess.run(
        shlex.split(os.environ["CADUCEUS_DNS_CMD"]) + [str(a) for a in selected],
        input=stdin_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    raise SystemExit(result.returncode)

if len(sys.argv) >= 3 and sys.argv[1:3] == ["exousia", "bind"]:
    print(json.dumps({"ok": True, "publicKey": "fixture-public", "epoch": "1"}))
    raise SystemExit(0)
elif len(sys.argv) >= 3 and sys.argv[1:3] == ["exousia", "verify"]:
    flags = envelope.get("flags", {}).get("exousia", {})
    pin = flags.get("pin", envelope.get("pin"))
    public_key = flags.get("publicKey", envelope.get("publicKey"))
    verified = (pin == "2468" and public_key == "fixture-public") or (
        pin == "9753" and public_key == "fixture-new"
    )
    print(json.dumps({"ok": True, "verified": verified}))
    raise SystemExit(0)
elif len(sys.argv) >= 3 and sys.argv[1:3] == ["exousia", "change"]:
    if envelope.get("oldPin") == "2468" and envelope.get("newPin") == "9753":
        print(json.dumps({"ok": True, "publicKey": "fixture-new", "epoch": "2"}))
    else:
        print(json.dumps({"ok": False, "firstMissingSignal": "fixture-staff-failure"}))
    raise SystemExit(0)

# File ingress keeps the selector in argv and the request in the envelope.
if (len(sys.argv) >= 2 and sys.argv[1] == "storage/upload/ingress") or (len(sys.argv) >= 4 and sys.argv[1:4] == ["storage", "upload", "ingress"]):
    payload = envelope.get("payload", {}) if isinstance(envelope, dict) else {}
    source = Path(payload.get("spoolPath", ""))
    target = Path(payload.get("targetPath", payload.get("path", "")))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source.read_bytes())
    print(json.dumps({"schema":"caduceus.staff.file_ingress.v1","ok":True,"mutationPerformed":True,"execution":"fixture-file-ingress","firstMissingSignal":"none"}))
    raise SystemExit(0)

# The contract shim exposes the exact public command while reusing the fixture actuator.
if len(sys.argv) >= 3 and sys.argv[1:3] == ["cert", "house-ca"]:
    payload = envelope.get("payload", {}) if isinstance(envelope, dict) else {}
    args = payload.get("args", []) if isinstance(payload, dict) else []
    if not args and isinstance(envelope, dict):
        args = envelope.get("args", [])
    sys.argv[1:] = list(args)

_source = Path(__file__).with_name("house_ca.py")
exec(compile(_source.read_text(), str(_source), "exec"), globals(), globals())
