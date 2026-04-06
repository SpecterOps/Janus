"""
Cobalt Strike REST API parser.

Pulls tasks from the teamserver REST API (Cobalt Strike 4.12+), normalizes
them into Janus TaskEvent / ResultEvent pairs.

See Fortra docs: REST API overview and Jobs/Tasks endpoints.
"""

from __future__ import annotations

import json
import re
import sys
import warnings
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import requests

from Core.io import write_bundle, write_ndjson
from Core.models import ResultEvent, TaskEvent, normalize_timestamp
SOURCE = "cobaltstrike-rest"
TOOL_NAME = "cobaltstrike"


def _endpoint_uses_loopback_host(endpoint: str) -> bool:
    try:
        parsed = urlparse(endpoint)
    except Exception:
        return False
    host = (parsed.hostname or "").lower().strip("[]")
    if not host:
        return False
    return host in ("localhost", "127.0.0.1", "::1")


def _likely_inside_container() -> bool:
    try:
        if Path("/.dockerenv").is_file():
            return True
    except OSError:
        pass
    try:
        text = Path("/proc/self/cgroup").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    markers = ("docker", "containerd", "kubepods", "libpod")
    return any(m in text for m in markers)


def _maybe_emit_docker_loopback_hint(base_url: str, exc: BaseException) -> None:
    if not isinstance(exc, requests.exceptions.ConnectionError):
        return
    if not _endpoint_uses_loopback_host(base_url):
        return
    if not _likely_inside_container():
        return
    print(
        "\njanus hint: cannot reach Cobalt Strike REST at a loopback URL from inside "
        "this container. Inside Docker, 127.0.0.1/localhost is the container, not the host.\n"
        "  Fix: use `janus-cli --docker-network host …` (Linux), set `rest_endpoint` to the "
        "teamserver IP or `https://host.docker.internal:…` where reachable, or pass "
        "`--docker-add-host host.docker.internal:host-gateway`.\n"
        "  See docs/FAQ.md — Cobalt Strike REST and janus-cli + Docker.\n",
        file=sys.stderr,
    )


def _split_command(data: str) -> tuple[str, str]:
    """Split a command string into (command_name, arguments_raw)."""
    parts = data.split(None, 1)
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[1]


def slugify(name: str) -> str:
    """Convert a name to a filesystem-safe slug."""
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-") or "op"


def coerce_cs_rest_task_id(task_id_str: str) -> int:
    """Map a Cobalt Strike string taskId to a stable positive int for Janus joins.

    CS REST uses opaque string IDs (e.g. ``hex-bid``). Janus uses int ``task_id``
    within an operation; this follows the same CRC32 approach as Ghostwriter
    fallbacks in ``Parsers/Ghostwriter/main.py``.
    """
    if not task_id_str or not str(task_id_str).strip():
        return 0
    hashed = zlib.crc32(str(task_id_str).strip().encode("utf-8")) & 0x7FFFFFFF
    return hashed if hashed else 1


def _parse_callback_id(bid: Any) -> tuple[int, int]:
    """Return (callback_id, callback_display_id) from REST ``bid``."""
    if bid is None:
        return 0, 0
    s = str(bid).strip()
    if not s:
        return 0, 0
    try:
        n = int(s, 10)
        return n, n
    except ValueError:
        return 0, 0


def _extract_bid(row: dict[str, Any] | None) -> str:
    """Return a normalized beacon id string from task or beacon payloads."""
    if not isinstance(row, dict):
        return ""
    for key in ("bid", "beaconId", "beacon_id", "id"):
        value = row.get(key)
        if value is None:
            continue
        bid = str(value).strip()
        if bid:
            return bid
    return ""


def _coerce_nonnegative_number(value: Any) -> float | None:
    """Best-effort numeric coercion for beacon sleep metadata."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        try:
            number = float(str(value).strip())
        except (TypeError, ValueError):
            return None
    if number < 0:
        return None
    return number


def _format_sleep_component(value: float) -> str:
    """Format numeric sleep/jitter values without noisy decimals."""
    if value.is_integer():
        return str(int(value))
    return f"{value:g}"


def _format_callback_sleep_info(beacon: dict[str, Any] | None) -> str:
    """Translate CS beacon sleep metadata into Janus callback_sleep_info."""
    if not isinstance(beacon, dict):
        return ""
    if beacon.get("supportsSleep") is False:
        return ""

    sleep_seconds: float | None = None
    jitter_percent: float | None = None
    sleep_value = beacon.get("sleep")

    if isinstance(sleep_value, dict):
        sleep_seconds = _coerce_nonnegative_number(
            sleep_value.get("sleep") or sleep_value.get("seconds") or sleep_value.get("interval")
        )
        jitter_percent = _coerce_nonnegative_number(sleep_value.get("jitter"))
    else:
        sleep_seconds = _coerce_nonnegative_number(
            sleep_value or beacon.get("sleepSeconds") or beacon.get("sleep_seconds")
        )
        jitter_percent = _coerce_nonnegative_number(
            beacon.get("jitter") or beacon.get("sleepJitter") or beacon.get("sleep_jitter")
        )

    if sleep_seconds is None:
        return ""

    text = f"{_format_sleep_component(sleep_seconds)}s"
    if jitter_percent is not None:
        text = f"{text} jitter={_format_sleep_component(jitter_percent)}"
    return text


def _login_token_from_body(body: dict[str, Any]) -> str | None:
    """Extract bearer token from CS login JSON (schema may vary by build)."""
    if not body:
        return None
    for key in ("access_token", "token", "bearerToken", "jwt", "id_token"):
        val = body.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    # Some APIs nest under data
    data = body.get("data")
    if isinstance(data, dict):
        return _login_token_from_body(data)
    return None


def infer_result_status(
    task_status: str | None,
    result_items: list[dict[str, Any]],
    error_items: list[Any],
) -> str:
    """Map REST task state to Janus result status (success | error | unknown)."""
    errors_norm = _normalize_error_items(error_items)
    if errors_norm:
        return "error"

    ts = (task_status or "").strip().upper()
    if ts in ("FAILED", "FAILURE", "ERROR", "CANCELLED", "CANCELED"):
        return "error"

    # Transitional / no output yet
    if ts in ("NOT_FOUND", "PENDING", "SUBMITTED", "QUEUED", "RUNNING", ""):
        if not result_items:
            return "unknown"

    # Delivered output (sample: OUTPUT_RECEIVED)
    if ts.endswith("_RECEIVED") or "RECEIVED" in ts:
        if result_items:
            return "success"
        return "unknown"

    if result_items:
        # Output present without a clear failure signal
        return "success"

    return "unknown"


def _normalize_error_items(error_items: list[Any]) -> list[str]:
    out: list[str] = []
    if not error_items:
        return out
    for item in error_items:
        if item is None:
            continue
        if isinstance(item, str):
            s = item.strip()
            if s:
                out.append(s)
        elif isinstance(item, dict):
            msg = item.get("message") or item.get("error") or item.get("text")
            if isinstance(msg, str) and msg.strip():
                out.append(msg.strip())
            else:
                out.append(json.dumps(item, sort_keys=True))
        else:
            out.append(str(item))
    return out


def _build_merged_output_text(
    acknowledgements: list[dict[str, Any]] | None,
    result_items: list[dict[str, Any]],
    error_items: list[Any],
) -> str:
    chunks: list[str] = []
    if acknowledgements:
        for ack in acknowledgements:
            if not isinstance(ack, dict):
                continue
            text = (ack.get("text") or "").strip()
            if not text:
                continue
            ts = ack.get("timestamp")
            prefix = f"[{ts}] " if ts else ""
            chunks.append(f"{prefix}{text}")
    for item in result_items:
        if not isinstance(item, dict):
            continue
        out = item.get("output")
        if isinstance(out, str) and out.strip():
            chunks.append(out.strip())
    err_texts = _normalize_error_items(error_items if isinstance(error_items, list) else [])
    for e in err_texts:
        chunks.append(f"[error] {e}")
    return "\n".join(chunks)


def _result_timestamp(
    detail: dict[str, Any],
    result_items: list[dict[str, Any]],
    acknowledgements: list[dict[str, Any]] | None,
) -> str | None:
    """Prefer latest explicit chunk timestamp, then updated, then created."""
    candidates: list[str] = []
    for item in result_items:
        if isinstance(item, dict) and item.get("timestamp"):
            candidates.append(str(item["timestamp"]))
    if acknowledgements:
        for ack in acknowledgements:
            if isinstance(ack, dict) and ack.get("timestamp"):
                candidates.append(str(ack["timestamp"]))
    for raw in candidates:
        try:
            return normalize_timestamp(raw)
        except (TypeError, ValueError):
            continue
    for key in ("updated", "created"):
        if detail.get(key):
            try:
                return normalize_timestamp(detail[key])
            except (TypeError, ValueError):
                pass
    return None


def normalize_cs_rest_task_detail(
    detail: dict[str, Any],
    operation_id: int,
    beacon_detail: dict[str, Any] | None = None,
) -> tuple[TaskEvent | None, ResultEvent | None, dict[str, Any]]:
    """Convert one CS REST task object (list row or GET detail) to events.

    Returns (task_event, result_event, stats). Either event can be None if
    the row is unusable (missing task id or timestamps).
    """
    stats: dict[str, Any] = {"skipped": False, "reason": ""}
    task_id_str = (detail.get("taskId") or detail.get("task_id") or "").strip()
    if not task_id_str:
        stats["skipped"] = True
        stats["reason"] = "missing taskId"
        return None, None, stats

    tid = coerce_cs_rest_task_id(task_id_str)
    if tid == 0:
        stats["skipped"] = True
        stats["reason"] = "task_id coerced to 0"
        return None, None, stats

    created_raw = detail.get("created")
    if not created_raw:
        stats["skipped"] = True
        stats["reason"] = "missing created"
        return None, None, stats
    try:
        task_ts = normalize_timestamp(created_raw)
    except (TypeError, ValueError) as exc:
        stats["skipped"] = True
        stats["reason"] = f"bad created timestamp: {exc}"
        return None, None, stats

    cmd_raw = (detail.get("taskCommand") or detail.get("command") or "").strip()
    cmd_name, args_raw = _split_command(cmd_raw) if cmd_raw else ("", "")

    task_bid = _extract_bid(detail)
    cb_id, cb_display = _parse_callback_id(task_bid or _extract_bid(beacon_detail))

    op_user = (detail.get("user") or "").strip()
    if op_user:
        extra = f"operator={op_user}"
        args_raw = f"{extra} {args_raw}".strip() if args_raw else extra

    task_event = TaskEvent(
        source=SOURCE,
        operation_id=operation_id,
        callback_id=cb_id,
        callback_display_id=cb_display if cb_display else cb_id,
        task_id=tid,
        display_id=tid,
        timestamp=task_ts,
        tool_name=TOOL_NAME,
        command_name=cmd_name or "(unknown)",
        arguments_raw=args_raw,
        callback_sleep_info=_format_callback_sleep_info(beacon_detail),
        c2_task_id=task_id_str,
    )

    result_items = detail.get("result") if isinstance(detail.get("result"), list) else []
    error_items = detail.get("error") if isinstance(detail.get("error"), list) else []
    acks = detail.get("taskAcknowledgements")
    if acks is not None and not isinstance(acks, list):
        acks = None

    task_status = detail.get("taskStatus")
    if isinstance(task_status, str):
        task_status_str = task_status
    else:
        task_status_str = str(task_status) if task_status is not None else None

    status = infer_result_status(task_status_str, result_items, error_items)
    output_text = _build_merged_output_text(acks or [], result_items, error_items)

    res_ts = _result_timestamp(detail, result_items, acks)
    if not res_ts:
        res_ts = task_ts

    result_event = ResultEvent(
        source=SOURCE,
        operation_id=operation_id,
        task_id=tid,
        timestamp=res_ts,
        status=status,
        output_text=output_text,
    )
    return task_event, result_event, stats


class CobaltStrikeRestClient:
    """HTTP client for Cobalt Strike REST API."""

    def __init__(
        self,
        base_url: str,
        verify_tls: bool = True,
        debug: bool = False,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.debug = debug
        self._session = session or requests.Session()
        if not self.verify_tls:
            self._session.verify = False
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        self._session.headers["Content-Type"] = "application/json"

    def _url(self, path: str) -> str:
        path = path if path.startswith("/") else f"/{path}"
        return f"{self.base_url}{path}"

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        try:
            return self._session.request(method, url, **kwargs)
        except requests.ConnectionError as exc:
            _maybe_emit_docker_loopback_hint(self.base_url, exc)
            raise

    def login(self, username: str, password: str, duration_ms: int = 86400000) -> None:
        url = self._url("/api/auth/login")
        body = {
            "username": username,
            "password": password,
            "duration_ms": int(duration_ms),
        }
        if self.debug:
            print(f"DEBUG POST {url}", file=sys.stderr)
        resp = self._request("POST", url, json=body, timeout=60)
        resp.raise_for_status()
        try:
            payload = resp.json()
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Cobalt Strike login returned non-JSON: {exc}") from exc
        token = _login_token_from_body(payload)
        if not token:
            raise RuntimeError(
                "Cobalt Strike login response missing token "
                f"(keys: {list(payload.keys()) if isinstance(payload, dict) else type(payload)})"
            )
        self._session.headers["Authorization"] = f"Bearer {token}"

    def set_token(self, token: str) -> None:
        """Use an existing bearer token (skip login)."""
        self._session.headers["Authorization"] = f"Bearer {token.strip()}"

    def list_tasks(self) -> list[dict[str, Any]]:
        url = self._url("/api/v1/tasks")
        if self.debug:
            print(f"DEBUG GET {url}", file=sys.stderr)
        resp = self._request("GET", url, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict) and isinstance(data.get("tasks"), list):
            return [x for x in data["tasks"] if isinstance(x, dict)]
        raise RuntimeError(
            f"Unexpected /api/v1/tasks response shape: {type(data).__name__}"
        )

    def get_task(self, task_id: str) -> dict[str, Any]:
        safe = quote(str(task_id), safe="-_.~")
        url = self._url(f"/api/v1/tasks/{safe}")
        if self.debug:
            print(f"DEBUG GET {url}", file=sys.stderr)
        resp = self._request("GET", url, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Unexpected task detail type: {type(data).__name__}")
        return data

    def list_beacons(self) -> list[dict[str, Any]]:
        url = self._url("/api/v1/beacons")
        if self.debug:
            print(f"DEBUG GET {url}", file=sys.stderr)
        resp = self._request("GET", url, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict) and isinstance(data.get("beacons"), list):
            return [x for x in data["beacons"] if isinstance(x, dict)]
        raise RuntimeError(
            f"Unexpected /api/v1/beacons response shape: {type(data).__name__}"
        )

    def get_beacon(self, bid: str) -> dict[str, Any]:
        safe = quote(str(bid), safe="-_.~")
        url = self._url(f"/api/v1/beacons/{safe}")
        if self.debug:
            print(f"DEBUG GET {url}", file=sys.stderr)
        resp = self._request("GET", url, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Unexpected beacon detail type: {type(data).__name__}")
        return data


class CobaltStrikeRestPullParser:
    """Fetch tasks from CS REST and normalize to Janus events."""

    SOURCE = SOURCE
    TOOL_NAME = TOOL_NAME

    def __init__(
        self,
        endpoint: str,
        username: str | None = None,
        password: str | None = None,
        api_token: str | None = None,
        duration_ms: int = 86400000,
        verify_tls: bool = True,
        debug: bool = False,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.username = username
        self.password = password
        self.api_token = api_token
        self.duration_ms = duration_ms
        self.verify_tls = verify_tls
        self.debug = debug

    def preflight(self) -> None:
        client = self._build_client()
        client.list_tasks()
        try:
            client.list_beacons()
        except (requests.RequestException, RuntimeError) as exc:
            if self.debug:
                print(f"warning: GET beacons failed during preflight: {exc}", file=sys.stderr)

    def normalize_from_details(
        self,
        details: list[dict[str, Any]],
        operation_id: int,
        operation_name: str,
        *,
        beacon_details: dict[str, dict[str, Any]] | None = None,
        beacon_fetch_metadata: dict[str, Any] | None = None,
        endpoint: str = "",
        skipped_list_rows: int = 0,
        fetch_errors: int = 0,
    ) -> tuple[list[TaskEvent], list[ResultEvent], dict[str, Any]]:
        task_events: list[TaskEvent] = []
        result_events: list[ResultEvent] = []
        skipped_rows = 0
        reasons: dict[str, int] = {}
        beacon_lookup = beacon_details or {}
        beacon_fetch_metadata = beacon_fetch_metadata or {}
        tasks_with_bid = 0
        tasks_without_bid = 0
        beacon_join_hits = 0
        beacon_join_misses = 0
        sleep_enriched_tasks = 0

        for detail in details:
            bid = _extract_bid(detail)
            beacon_detail = None
            if bid:
                tasks_with_bid += 1
                beacon_detail = beacon_lookup.get(bid)
                if beacon_detail is not None:
                    beacon_join_hits += 1
                else:
                    beacon_join_misses += 1
            else:
                tasks_without_bid += 1

            te, re, stats = normalize_cs_rest_task_detail(
                detail,
                operation_id,
                beacon_detail=beacon_detail,
            )
            if stats.get("skipped"):
                skipped_rows += 1
                r = stats.get("reason") or "unknown"
                reasons[r] = reasons.get(r, 0) + 1
                continue
            if te is not None:
                if te.callback_sleep_info:
                    sleep_enriched_tasks += 1
                task_events.append(te)
            if re is not None:
                result_events.append(re)

        status_counts: dict[str, int] = {"success": 0, "error": 0, "unknown": 0}
        for re in result_events:
            status_counts[re.status] = status_counts.get(re.status, 0) + 1

        metadata: dict[str, Any] = {
            "source": self.SOURCE,
            "tool_name": self.TOOL_NAME,
            "operation_id": operation_id,
            "operation_name": operation_name,
            "operation_slug": slugify(operation_name),
            "cobaltstrike_rest_endpoint": endpoint or self.endpoint,
            "task_count": len(task_events),
            "result_count": len(result_events),
            "status_counts": status_counts,
            "skipped_task_rows": skipped_rows,
            "skip_reasons": reasons,
            "skipped_list_rows": skipped_list_rows,
            "task_fetch_errors": fetch_errors,
            "beacon_count": len(beacon_lookup),
            "beacon_list_rows": beacon_fetch_metadata.get("list_rows", 0),
            "beacon_list_skipped_rows": beacon_fetch_metadata.get("skipped_rows", 0),
            "beacon_list_fetch_errors": beacon_fetch_metadata.get("list_fetch_errors", 0),
            "beacon_detail_fetches": beacon_fetch_metadata.get("detail_fetches", 0),
            "beacon_detail_fetch_errors": beacon_fetch_metadata.get("detail_fetch_errors", 0),
            "tasks_with_bid": tasks_with_bid,
            "tasks_without_bid": tasks_without_bid,
            "beacon_join_hits": beacon_join_hits,
            "beacon_join_misses": beacon_join_misses,
            "sleep_enriched_tasks": sleep_enriched_tasks,
            "beacon_task_detail_source": "task-endpoints-only",
            "beacon_task_detail_used": False,
            "beacon_task_detail_reason": (
                "not_used; current ingest relies on /api/v1/tasks and /api/v1/tasks/{taskId}"
            ),
        }
        return task_events, result_events, metadata

    def _build_client(self) -> CobaltStrikeRestClient:
        client = CobaltStrikeRestClient(
            base_url=self.endpoint,
            verify_tls=self.verify_tls,
            debug=self.debug,
        )
        if self.api_token:
            client.set_token(self.api_token)
        else:
            if not self.username or not self.password:
                raise ValueError("username and password required when api_token is not set")
            client.login(self.username, self.password, duration_ms=self.duration_ms)
        return client

    def fetch_beacon_details(
        self,
        client: CobaltStrikeRestClient | None = None,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
        """Return merged beacon detail dicts keyed by bid and fetch metadata."""
        client = client or self._build_client()
        beacon_by_bid: dict[str, dict[str, Any]] = {}
        metadata: dict[str, Any] = {
            "list_rows": 0,
            "skipped_rows": 0,
            "list_fetch_errors": 0,
            "detail_fetches": 0,
            "detail_fetch_errors": 0,
        }

        try:
            summaries = client.list_beacons()
        except (requests.RequestException, RuntimeError) as exc:
            metadata["list_fetch_errors"] = 1
            if self.debug:
                print(f"warning: GET beacons failed: {exc}", file=sys.stderr)
            return beacon_by_bid, metadata

        metadata["list_rows"] = len(summaries)
        for row in summaries:
            bid = _extract_bid(row)
            if not bid:
                metadata["skipped_rows"] += 1
                continue
            if bid not in beacon_by_bid:
                beacon_by_bid[bid] = dict(row)
            else:
                deep_update(beacon_by_bid[bid], row)

        for bid, row in beacon_by_bid.items():
            if _format_callback_sleep_info(row):
                continue
            try:
                metadata["detail_fetches"] += 1
                full = client.get_beacon(bid)
                deep_update(row, full)
            except (requests.RequestException, RuntimeError) as exc:
                metadata["detail_fetch_errors"] += 1
                if self.debug:
                    print(f"warning: GET beacon {bid!r} failed: {exc}", file=sys.stderr)

        return beacon_by_bid, metadata

    def fetch_all_task_details(
        self,
    ) -> tuple[list[dict[str, Any]], int, int, dict[str, dict[str, Any]], dict[str, Any]]:
        """Return task details plus optional beacon enrichment metadata."""
        client = self._build_client()

        summaries = client.list_tasks()
        merged_by_id: dict[str, dict[str, Any]] = {}
        order: list[str] = []

        skipped_list = 0
        for row in summaries:
            tid = (row.get("taskId") or row.get("task_id") or "").strip()
            if not tid:
                skipped_list += 1
                continue
            if tid not in merged_by_id:
                merged_by_id[tid] = dict(row)
                order.append(tid)
            else:
                deep_update(merged_by_id[tid], row)

        fetch_errors = 0
        out: list[dict[str, Any]] = []

        for tid in order:
            row = merged_by_id[tid]
            needs_fetch = not _detail_has_output_fields(row)
            if needs_fetch:
                try:
                    full = client.get_task(tid)
                    deep_update(row, full)
                except requests.RequestException as exc:
                    fetch_errors += 1
                    if self.debug:
                        print(f"warning: GET task {tid!r} failed: {exc}", file=sys.stderr)
            out.append(row)

        beacon_details, beacon_fetch_metadata = self.fetch_beacon_details(client)
        return out, skipped_list, fetch_errors, beacon_details, beacon_fetch_metadata


def deep_update(dst: dict[str, Any], src: dict[str, Any]) -> None:
    """Merge src into dst (shallow keys; nested dicts merged one level)."""
    for k, v in src.items():
        if k in dst and isinstance(dst[k], dict) and isinstance(v, dict):
            dst[k] = {**dst[k], **v}
        else:
            dst[k] = v


def _detail_has_output_fields(row: dict[str, Any]) -> bool:
    """True if this object already looks like a task detail (not just list summary)."""
    if row.get("result") is not None:
        return True
    if row.get("error") is not None:
        return True
    if row.get("taskAcknowledgements") is not None:
        return True
    return False


def run_cobaltstrike_rest_ingest(
    parser: CobaltStrikeRestPullParser,
    operation_id: int,
    operation_name: str,
    out_dir: Path,
    analysis_timestamp: datetime | None = None,
    output_rule: str = "all",
    arguments_rule: str = "all",
) -> dict[str, Any]:
    """Fetch REST tasks, normalize, apply retention policy, write artifacts."""
    from Core.output_rule import (
        apply_arguments_rule_to_tasks,
        apply_output_rule_to_results,
        normalize_arguments_rule,
        normalize_output_rule,
    )

    details, skipped_f, fetch_err, beacon_details, beacon_fetch_metadata = parser.fetch_all_task_details()
    task_events, result_events, metadata = parser.normalize_from_details(
        details,
        operation_id,
        operation_name,
        beacon_details=beacon_details,
        beacon_fetch_metadata=beacon_fetch_metadata,
        endpoint=parser.endpoint,
        skipped_list_rows=skipped_f,
        fetch_errors=fetch_err,
    )
    apply_arguments_rule_to_tasks(task_events, arguments_rule)
    apply_output_rule_to_results(result_events, output_rule)
    rule_applied = normalize_output_rule(output_rule)
    args_rule_applied = normalize_arguments_rule(arguments_rule)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if analysis_timestamp is None:
        analysis_timestamp = datetime.now(timezone.utc)

    events_path = out_dir / "events.ndjson"
    bundle_path = out_dir / "bundle.json"

    all_events = [e.to_dict() for e in task_events] + [e.to_dict() for e in result_events]
    write_ndjson(all_events, events_path)

    meta = dict(metadata)
    meta["output_rule"] = rule_applied
    meta["arguments_rule"] = args_rule_applied
    meta["events_path"] = events_path.name
    write_bundle(meta, bundle_path, analysis_timestamp)
    return meta
