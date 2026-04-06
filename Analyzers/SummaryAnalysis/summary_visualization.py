"""
SummaryVisualization — At-a-glance operation health.

Computes two datasets for the report header visualizations:

1. **Status distribution** — counts of success / error / unknown results
   for a pie chart.
2. **Command volume timeline** — task counts bucketed by calendar hour
   (or by day when the operation spans more than 72 hours) for a bar chart.

No heuristics.  Source-agnostic — works with any parser output.
"""

from collections import defaultdict
from datetime import datetime, timedelta


def _parse_ts(iso_str: str) -> datetime | None:
    """Best-effort ISO timestamp parse."""
    if not iso_str:
        return None
    try:
        return datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def analyze(task_events: list[dict], result_events: list[dict]) -> dict:
    """Produce status distribution and command volume timeline.

    Args:
        task_events: Normalized task event dicts.
        result_events: Normalized result event dicts.

    Returns:
        Dict with ``status_distribution`` and ``timeline`` keys.
    """

    # --- Status distribution from result events ---
    status_counts: dict[str, int] = {"success": 0, "error": 0, "unknown": 0}
    for r in result_events:
        status = r.get("status", "unknown")
        if status in status_counts:
            status_counts[status] += 1
        else:
            status_counts["unknown"] += 1

    total_results = sum(status_counts.values())

    # --- Command volume timeline from task events ---
    timestamps: list[datetime] = []
    for t in task_events:
        dt = _parse_ts(t.get("timestamp", ""))
        if dt is not None:
            timestamps.append(dt)

    timeline_buckets: list[dict] = []
    bucket_unit = "hour"

    if timestamps:
        timestamps.sort()
        span = timestamps[-1] - timestamps[0]

        if span > timedelta(hours=72):
            bucket_unit = "day"
            # Bucket by calendar day (UTC)
            day_counts: dict[str, int] = defaultdict(int)
            for dt in timestamps:
                key = dt.strftime("%Y-%m-%d")
                day_counts[key] += 1

            # Fill gaps so every day in the range has an entry
            start_date = timestamps[0].date()
            end_date = timestamps[-1].date()
            current = start_date
            while current <= end_date:
                key = current.isoformat()
                timeline_buckets.append({
                    "label": key,
                    "count": day_counts.get(key, 0),
                })
                current += timedelta(days=1)
        else:
            bucket_unit = "hour"
            hour_counts: dict[str, int] = defaultdict(int)
            for dt in timestamps:
                key = dt.strftime("%Y-%m-%d %H:00")
                hour_counts[key] += 1

            # Fill gaps
            start_hour = timestamps[0].replace(minute=0, second=0, microsecond=0)
            end_hour = timestamps[-1].replace(minute=0, second=0, microsecond=0)
            current_hour = start_hour
            while current_hour <= end_hour:
                key = current_hour.strftime("%Y-%m-%d %H:00")
                timeline_buckets.append({
                    "label": key,
                    "count": hour_counts.get(key, 0),
                })
                current_hour += timedelta(hours=1)

    return {
        "analyzer": "summary-visualization",
        "status_distribution": {
            "success": status_counts["success"],
            "error": status_counts["error"],
            "unknown": status_counts["unknown"],
            "total": total_results,
        },
        "timeline": {
            "bucket_unit": bucket_unit,
            "buckets": timeline_buckets,
        },
        "summary": {
            "total_tasks": len(task_events),
            "total_results": total_results,
            "timeline_buckets": len(timeline_buckets),
            "span_hours": round((timestamps[-1] - timestamps[0]).total_seconds() / 3600, 1) if len(timestamps) >= 2 else 0,
        },
    }
