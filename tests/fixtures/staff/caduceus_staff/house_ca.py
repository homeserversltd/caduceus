"""Integration shim: exercise the promoted production actuator in fixtures."""
from pathlib import Path

_source = Path(__file__).parents[4] / "data/staff-actuators/caduceus_staff/house_ca.py"
exec(compile(_source.read_text(), str(_source), "exec"), globals(), globals())
