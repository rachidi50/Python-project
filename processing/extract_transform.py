"""Compatibility entry point for structured SSH authentication extraction."""
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from log_analyser.pipeline import extract as extract_event


def extract(row, year=None):
    """Return an SSH event or None; pass the log year for historical syslog."""
    return extract_event(row, datetime.now().year if year is None else year)
