#!/usr/bin/env python3
import sys
# The contract shim exposes the exact public command while reusing the fixture actuator.
if len(sys.argv) >= 3 and sys.argv[1:3] == ["cert", "house-ca"]:
    sys.argv[1:3] = []
from pathlib import Path
_source = Path(__file__).with_name("house_ca.py")
exec(compile(_source.read_text(), str(_source), "exec"), globals(), globals())
