"""Cobalt Strike REST parser."""

from .cobalt_strike_rest import CobaltStrikeRestPullParser, run_cobaltstrike_rest_ingest

__all__ = [
    "CobaltStrikeRestPullParser",
    "run_cobaltstrike_rest_ingest",
]
