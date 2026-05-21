"""Run Slither's built-in detectors and shape the output to our Finding model."""
from __future__ import annotations
import inspect
from pathlib import Path

from slither import Slither
from slither.detectors import all_detectors

from ..config import SLITHER_DETECTORS
from ..models import Finding, Location


# all_detectors exports modules AND helper functions alongside detector classes.
# Without inspect.isclass(), the comprehension picks up non-classes that happen
# to have an ARGUMENT attribute and Slither.register_detector then raises a
# cryptic TypeError. Filtering by isclass keeps us safe across Slither versions.
_DETECTOR_CLASSES = {
    cls.ARGUMENT: cls
    for cls in all_detectors.__dict__.values()
    if inspect.isclass(cls) and hasattr(cls, "ARGUMENT") and cls.ARGUMENT
}

_SEVERITY_MAP = {
    "High": "High", "Medium": "Medium", "Low": "Low",
    "Informational": "Informational", "Optimization": "Low",
}


def run_slither(source_path: Path) -> list[Finding]:
    sl = Slither(str(source_path))
    findings: list[Finding] = []
    idx = 1
    for det_id in SLITHER_DETECTORS:
        det_cls = _DETECTOR_CLASSES.get(det_id)
        if det_cls is None:
            continue
        sl.register_detector(det_cls)

    results = sl.run_detectors()
    # results is a list-of-list (one per detector)
    for det_results in results:
        for r in det_results:
            elements = r.get("elements", [])
            loc = _location_from_elements(elements)
            findings.append(Finding(
                id=f"v{idx:03d}",
                detector_id=r.get("check", "unknown"),
                severity=_SEVERITY_MAP.get(r.get("impact", "Low"), "Low"),
                location=loc,
                description=r.get("description", "").strip(),
                extra={"confidence": r.get("confidence")},
            ))
            idx += 1
    return findings


def _location_from_elements(elements) -> Location:
    if not elements:
        return Location(file="", line=0)
    el = elements[0]
    sm = el.get("source_mapping", {}) or {}
    filename = sm.get("filename_short") or sm.get("filename_relative") or sm.get("filename_absolute", "")
    lines = sm.get("lines") or [0]
    func_name = None
    if el.get("type") == "function":
        func_name = el.get("name")
    return Location(file=str(filename), line=lines[0], function_name=func_name)
