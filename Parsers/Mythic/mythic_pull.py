"""
Mythic pull-mode parser.

Connects to Mythic GraphQL endpoint, pulls tasks and operator-visible output,
and normalizes them into task and result events.
"""

import json
import re
import ssl
import sys
import warnings
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter

from Core.io import write_bundle, write_ndjson
from Core.models import ResultEvent, TaskEvent, normalize_timestamp
from Core.output_rule import (
    ARGUMENTS_RULE_ALL,
    OUTPUT_RULE_ALL,
    apply_arguments_rule_to_tasks,
    apply_output_rule_to_results,
    normalize_arguments_rule,
    normalize_output_rule,
)
from Parsers.Mythic.gql_queries import (
    INTERACTIVE_MESSAGES_QUERY,
    OPERATION_QUERY,
    PARENT_TASKS_BY_ID_QUERY,
    PREFLIGHT_TASK_QUERY,
    RESPONSES_PAGE_QUERY,
    TASKS_QUERY,
)
from Parsers.Mythic.pty_ingest import (
    build_synthetics_from_child_pty_tasks,
    build_synthetics_from_interactive_stream,
    group_interactive_by_parent_task_id,
)

RESPONSES_PAGE_SIZE = 500


def slugify(name: str) -> str:
    """Convert an operation name to a filesystem-safe slug.

    Lowercase, replace non-alphanumeric runs with a single hyphen, strip
    leading/trailing hyphens.  Returns 'unnamed' for empty input.
    """
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "unnamed"


class _LegacyTLSAdapter(HTTPAdapter):
    """HTTP adapter that uses a maximally permissive SSL context for --insecure mode.

    Handles self-hosted Mythic servers that may use:
    - Self-signed certificates (check_hostname=False, CERT_NONE)
    - Legacy TLS renegotiation (OP_LEGACY_SERVER_CONNECT)
    - Older TLS versions or weak cipher suites (@SECLEVEL=0)

    ssl.create_default_context() enforces TLS 1.2+ and a high security level even
    when verify=False, which causes [SSL] record layer failures against older
    server configs. PROTOCOL_TLS_CLIENT with explicit minimum-version negotiation
    and SECLEVEL=0 bypasses those restrictions.
    """

    @staticmethod
    def _make_ssl_context() -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Allow legacy TLS renegotiation (Python 3.12+; no-op on older builds)
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        # Lower the minimum TLS version as far as the local OpenSSL build allows
        for version in (
            getattr(ssl.TLSVersion, "TLSv1", None),
            getattr(ssl.TLSVersion, "TLSv1_1", None),
            getattr(ssl.TLSVersion, "TLSv1_2", None),
        ):
            if version is None:
                continue
            try:
                ctx.minimum_version = version
                break
            except (ssl.SSLError, AttributeError):
                continue
        # Remove OpenSSL security-level floor so weak DH/RSA params don't block
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        return ctx

    def send(self, request, *args, **kwargs):
        # Force verify=False so requests doesn't reconfigure SSL after our
        # custom context is already set on the pool manager.
        kwargs["verify"] = False
        return super().send(request, *args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._make_ssl_context()
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["ssl_context"] = self._make_ssl_context()
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class MythicPullParser:
    """Pull-mode parser for Mythic C2 GraphQL API."""

    def __init__(self, endpoint: str, api_token: str, verify_tls: bool = True, debug: bool = False):
        self.endpoint = endpoint.rstrip("/")
        self.api_token = api_token
        self.verify_tls = verify_tls
        self.debug = debug
        self._last_pty_interactive_query_available = False
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"
        self._session.headers["apitoken"] = api_token
        if not verify_tls:
            self._session.mount("https://", _LegacyTLSAdapter())
            self._session.verify = False
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    def _execute_query(self, query: str) -> dict:
        """POST GraphQL query and return data. Raise on HTTP or GraphQL errors."""
        # Minimal payload: query only. Variables/operationName can trigger PersistedQueryNotSupported.
        # Send raw JSON string to match curl format exactly (no extra keys from json.dumps).
        body = json.dumps({"query": query}, separators=(",", ":"))
        url = self.endpoint.rstrip("/")
        if "/graphql" not in url:
            url = f"{url}/graphql/"
        if not url.endswith("/"):
            url = f"{url}/"
        if self.debug:
            print(f"DEBUG POST {url}\nDEBUG body: {body}", file=sys.stderr)
        resp = self._session.post(url, data=body, timeout=30)
        if self.debug:
            print(f"DEBUG status: {resp.status_code}\nDEBUG response: {resp.text[:500]}", file=sys.stderr)
        resp.raise_for_status()
        data = resp.json()
        if "errors" in data and data["errors"]:
            err_msg = "; ".join(e.get("message", str(e)) for e in data["errors"])
            raise RuntimeError(f"GraphQL error: {err_msg}")
        if "data" not in data:
            raise RuntimeError("GraphQL response missing 'data' key - schema may have changed")
        return data["data"]

    def fetch_tasks(self, operation_id: int) -> list[dict]:
        """Fetch tasks for the given operation."""
        data = self._execute_query(TASKS_QUERY % operation_id)
        if "task" not in data:
            raise KeyError("GraphQL response missing 'task' key - schema may have changed")
        rows = data["task"]
        for row in rows:
            for field in ("id", "callback_id", "command_name", "original_params", "status", "completed", "timestamp", "status_timestamp_submitted", "status_timestamp_processing", "status_timestamp_processed", "operation_id"):
                if field not in row:
                    raise KeyError(f"Task row missing field '{field}' - schema may have changed")
            for field in ("id", "command_name", "completed"):
                if row[field] is None:
                    raise ValueError(f"Task row has null '{field}' - schema may have changed")
            if "stdout" not in row or row.get("stdout") is None:
                row["stdout"] = ""
            if "stderr" not in row or row.get("stderr") is None:
                row["stderr"] = ""
            if "agent_task_id" not in row or row.get("agent_task_id") is None:
                row["agent_task_id"] = ""
            # Validate command join (contains payload type and original command name)
            if "command" in row and row["command"]:
                if "cmd" not in row["command"]:
                    raise KeyError("Task.command missing 'cmd' field - schema may have changed")
                if "payloadtype" not in row["command"]:
                    raise KeyError("Task.command missing 'payloadtype' field - schema may have changed")
        return rows

    def fetch_responses(self, operation_id: int) -> list[dict]:
        """Fetch responses (operator-visible output) for the given operation."""
        all_rows: list[dict] = []
        last_seen_id = 0
        page_number = 0

        while True:
            page_number += 1
            data = self._execute_query(
                RESPONSES_PAGE_QUERY % (operation_id, last_seen_id, RESPONSES_PAGE_SIZE)
            )
            if "response" not in data:
                raise KeyError("GraphQL response missing 'response' key - schema may have changed")
            rows = data["response"]
            for row in rows:
                for field in ("id", "task_id", "response_text", "timestamp"):
                    if field not in row:
                        raise KeyError(f"Response row missing field '{field}' - schema may have changed")
                if row["response_text"] is None:
                    raise ValueError("Response row has null 'response_text' - schema may have changed")
            if self.debug:
                page_last_id = rows[-1]["id"] if rows else last_seen_id
                print(
                    f"DEBUG response page {page_number}: fetched {len(rows)} row(s); last_id={page_last_id}",
                    file=sys.stderr,
                )
            if not rows:
                break
            all_rows.extend(rows)
            last_seen_id = rows[-1]["id"]
            if len(rows) < RESPONSES_PAGE_SIZE:
                break

        return all_rows

    def fetch_interactive_messages(self, operation_id: int) -> tuple[list[dict], bool]:
        """Fetch interactive PTY message rows when Hasura exposes the ``interactive`` root field.

        Returns (rows, available). When the field is missing (older Mythic), returns ([], False)
        without raising.
        """
        try:
            data = self._execute_query(INTERACTIVE_MESSAGES_QUERY % operation_id)
        except RuntimeError as exc:
            err = str(exc).lower()
            if "interactive" in err or "cannot query field" in err or "unknown field" in err:
                return [], False
            raise
        rows = data.get("interactive")
        if rows is None:
            return [], False
        for row in rows:
            for field in ("id", "task_id", "message_type", "data", "timestamp"):
                if field not in row:
                    raise KeyError(
                        f"interactive row missing field '{field}' — Mythic GraphQL schema may have changed"
                    )
        return rows, True

    def fetch_operation_name(self, operation_id: int) -> str:
        """Fetch the human-readable operation name from Mythic.

        Falls back to ``op-{operation_id}`` if the query fails or returns
        no rows (e.g. older Mythic version without the operation table).
        """
        fallback = f"op-{operation_id}"
        try:
            data = self._execute_query(OPERATION_QUERY % operation_id)
            rows = data.get("operation", [])
            if rows and rows[0].get("name"):
                return rows[0]["name"]
        except Exception as exc:
            print(
                f"warning: could not fetch operation name (falling back to '{fallback}'): {exc}",
                file=sys.stderr,
            )
        return fallback

    def preflight(self, operation_id: int | None = None) -> None:
        """Validate endpoint reachability + auth with a lightweight GraphQL call."""
        if operation_id is not None:
            # Use a minimal task query instead of the operation table so preflight
            # stays compatible with older Mythic schemas that still expose tasks
            # and responses but not the operation query.
            self._execute_query(PREFLIGHT_TASK_QUERY % operation_id)
            return
        self._execute_query("{__typename}")

    def normalize(self, operation_id: int) -> tuple[list[TaskEvent], list[ResultEvent]]:
        """Fetch tasks and responses, normalize into task and result events."""
        tasks = self.fetch_tasks(operation_id)
        responses = self.fetch_responses(operation_id)
        interactive_rows, pty_interactive_available = self.fetch_interactive_messages(operation_id)
        self._last_pty_interactive_query_available = pty_interactive_available

        # Group responses by task_id, concatenate response_text by timestamp
        by_task: dict[int, list[tuple[str, str]]] = defaultdict(list)
        for r in responses:
            task_id = r["task_id"]
            response_text = r.get("response_text")
            if response_text is None:
                response_text = ""
            else:
                response_text = str(response_text)
            by_task[task_id].append((normalize_timestamp(r["timestamp"]), response_text))

        for task_id in by_task:
            by_task[task_id].sort(key=lambda x: x[0])

        task_events: list[TaskEvent] = []
        result_events: list[ResultEvent] = []

        # Build lookup and find tasks that are pure dispatchers (parent of ≥1 sub-task
        # in this operation). These are skipped because the sub-task carries the
        # actual execution; the dispatcher just says "I spawned it."
        task_by_id: dict[int, dict] = {t["id"]: t for t in tasks}

        # Collect parent IDs that belong to a different operation (cross-op sub-tasking,
        # e.g. forge payloads spawning inline_assembly tasks in the Apollo operation).
        orphaned_parent_ids = {
            t["parent_task_id"]
            for t in tasks
            if t.get("parent_task_id") is not None and t["parent_task_id"] not in task_by_id
        }

        # Supplementary query to resolve cross-operation parent tasks.
        if orphaned_parent_ids:
            try:
                id_list = ", ".join(str(i) for i in sorted(orphaned_parent_ids))
                extra_data = self._execute_query(PARENT_TASKS_BY_ID_QUERY % id_list)
                for row in extra_data.get("task", []):
                    task_by_id[row["id"]] = row  # only id + command_name needed for attribution
            except Exception as exc:
                print(
                    f"warning: could not resolve {len(orphaned_parent_ids)} cross-operation parent task(s): {exc}",
                    file=sys.stderr,
                )

        dispatcher_task_ids: set[int] = {
            t["parent_task_id"]
            for t in tasks
            if t.get("parent_task_id") is not None and t["parent_task_id"] in task_by_id
        }

        pty_parent_ids: set[int] = {
            tid for tid in dispatcher_task_ids if task_by_id.get(tid, {}).get("command_name") == "pty"
        }

        interactive_by_parent = group_interactive_by_parent_task_id(interactive_rows, task_by_id)

        children_by_parent: dict[int, list[dict]] = defaultdict(list)
        for t in tasks:
            p = t.get("parent_task_id")
            if p is not None:
                children_by_parent[int(p)].append(t)

        suppressed_task_ids: set[int] = set()
        synthetic_task_events: list[TaskEvent] = []
        synthetic_result_events: list[ResultEvent] = []
        parent_preface: dict[int, str] = {}
        parent_exit_info: dict[int, dict] = {}

        for parent_id in pty_parent_ids:
            parent_row = task_by_id[parent_id]
            children = [c for c in children_by_parent.get(parent_id, []) if c.get("command_name") == "pty"]
            ims = interactive_by_parent.get(parent_id, [])
            if ims:
                st, sr, _, preface, exit_info = build_synthetics_from_interactive_stream(
                    operation_id, parent_row, ims
                )
                synthetic_task_events.extend(st)
                synthetic_result_events.extend(sr)
                if preface:
                    parent_preface[parent_id] = preface
                if exit_info:
                    parent_exit_info[parent_id] = exit_info
                suppressed_task_ids.update(int(c["id"]) for c in children)
            elif children:
                st, sr, sup = build_synthetics_from_child_pty_tasks(
                    operation_id, parent_row, children
                )
                synthetic_task_events.extend(st)
                synthetic_result_events.extend(sr)
                suppressed_task_ids |= sup

        for t in tasks:
            task_id = t["id"]

            if task_id in suppressed_task_ids:
                continue

            # Skip dispatcher parents — except PTY session launches (long-lived parent task).
            if task_id in dispatcher_task_ids and task_id not in pty_parent_ids:
                continue

            original_params = t["original_params"]
            if original_params is None:
                arguments_raw = ""
            elif isinstance(original_params, str):
                arguments_raw = original_params
            else:
                arguments_raw = json.dumps(original_params)

            raw_command_name = t["command_name"]

            # Use submitted timestamp (operator action time); fall back to
            # row timestamp if submitted is not set.
            submitted_ts = t.get("status_timestamp_submitted")
            task_timestamp = normalize_timestamp(submitted_ts if submitted_ts else t["timestamp"])

            callback_id = t.get("callback_id") or 0
            callback_data = t.get("callback") or {}
            callback_display_id = callback_data.get("display_id") or 0
            callback_sleep_info = callback_data.get("sleep_info") or ""
            display_id = t.get("display_id") or 0

            processing_ts_raw = t.get("status_timestamp_processing")
            processing_timestamp = normalize_timestamp(processing_ts_raw) if processing_ts_raw else ""

            # Attribute sub-tasks to the operator's original command (the parent).
            # e.g. forge_net_SharpSCCM → inline_assembly, jump_wmi → wmiexecute

            # Determine command attribution based on payload type.
            # For forge commands, Mythic stores the executed command (e.g. inline_assembly)
            # in command_name, but the original command (e.g. forge_net_SharpSCCM) is
            # available via the command.cmd field.
            command_data = t.get("command", {})
            payload_type_data = command_data.get("payloadtype") if command_data else None
            payload_type = payload_type_data.get("name", "") if payload_type_data else ""

            # For forge commands, use the original command name for attribution
            if payload_type == "forge":
                original_command = command_data.get("cmd", t["command_name"])
                executed_command = t["command_name"]
                # If the command was transformed, set issued_command_name
                if original_command != executed_command:
                    command_name = original_command
                    issued_command_name = executed_command
                else:
                    command_name = original_command
                    issued_command_name = ""
            else:
                command_name = t["command_name"]
                issued_command_name = ""

            parent_task_id = t.get("parent_task_id")
            orphaned_subtask = False

            # Handle subtasks: if parent_task_id is set, attribute to parent's command
            # This logic runs AFTER forge attribution, so forge commands that create
            # subtasks will have both attributions applied correctly.
            if parent_task_id is not None and parent_task_id in task_by_id:
                parent = task_by_id[parent_task_id]
                issued_command_name = command_name
                command_name = parent["command_name"]
            elif parent_task_id is not None:
                # parent_task_id set but unresolvable even after supplementary query
                orphaned_subtask = True
                print(
                    f"warning: task {task_id} has unresolvable parent_task_id={parent_task_id}",
                    file=sys.stderr,
                )

            task_retention: dict = {}
            pty_transport_event = False
            pty_session = False
            pty_parent_task_id = None
            pty_child_count = None
            pty_interactive_message_count = None
            if (
                parent_task_id is not None
                and parent_task_id in task_by_id
                and task_by_id[parent_task_id].get("command_name") == "pty"
                and raw_command_name == "pty"
            ):
                pty_transport_event = True
                pty_parent_task_id = parent_task_id
            if task_id in pty_parent_ids:
                pty_session = True
                pty_child_count = sum(
                    1
                    for c in children_by_parent.get(task_id, [])
                    if c.get("command_name") == "pty"
                )
                pty_interactive_message_count = len(interactive_by_parent.get(task_id, []))

            task_events.append(
                TaskEvent(
                    source="mythic",
                    operation_id=operation_id,
                    callback_id=callback_id,
                    callback_display_id=callback_display_id,
                    task_id=task_id,
                    display_id=display_id,
                    timestamp=task_timestamp,
                    tool_name="mythic",
                    command_name=command_name,
                    arguments_raw=arguments_raw,
                    processing_timestamp=processing_timestamp,
                    callback_sleep_info=callback_sleep_info,
                    issued_command_name=issued_command_name,
                    parent_task_id=parent_task_id,
                    orphaned_subtask=orphaned_subtask,
                    pty_session=pty_session,
                    pty_transport_event=pty_transport_event,
                    pty_parent_task_id=pty_parent_task_id,
                    pty_child_count=pty_child_count,
                    pty_interactive_message_count=pty_interactive_message_count,
                    retention_meta=task_retention,
                )
            )

            output_parts = by_task.get(task_id, [])
            output_text = "\n".join(part for _, part in output_parts) if output_parts else ""

            # Determine result timestamp: prefer task completion time, fall back to
            # last response timestamp, then task timestamp (for incomplete tasks
            # with no responses — likely callback crash/hang).
            status_ts = t.get("status_timestamp_processed")
            if status_ts:
                result_timestamp = normalize_timestamp(status_ts)
            elif output_parts:
                result_timestamp = output_parts[-1][0]
            else:
                result_timestamp = task_timestamp

            status, dispatch_failed = ResultEvent.determine_status(t["completed"], t["status"])

            result_retention: dict = {}
            exit_info = parent_exit_info.get(task_id, {})

            result_events.append(
                ResultEvent(
                    source="mythic",
                    operation_id=operation_id,
                    task_id=task_id,
                    timestamp=result_timestamp,
                    status=status,
                    dispatch_failed=dispatch_failed,
                    output_text=output_text,
                    pty_output_preface=parent_preface.get(task_id, ""),
                    pty_exit_observed=bool(exit_info.get("pty_exit_observed")),
                    pty_exit_timestamp=exit_info.get("pty_exit_timestamp", ""),
                    pty_exit_code=exit_info.get("pty_exit_code"),
                    retention_meta=result_retention,
                )
            )

        task_events.extend(synthetic_task_events)
        result_events.extend(synthetic_result_events)

        self._promote_terminal_unknowns(task_events, result_events)
        return task_events, result_events

    @staticmethod
    def _promote_terminal_unknowns(task_events: list[TaskEvent], result_events: list[ResultEvent]) -> None:
        """Promote callback-terminal unknowns to inferred errors.

        Strict rule: if an unknown result has no later task or result activity on
        the same (operation_id, callback_id), treat it as a terminal inferred error.
        """
        task_by_id: dict[tuple[int, int], TaskEvent] = {}
        callback_last_activity: dict[tuple[int, int], str] = {}

        for t in task_events:
            task_key = (t.operation_id, t.task_id)
            callback_key = (t.operation_id, t.callback_id)
            task_by_id[task_key] = t
            last_seen = callback_last_activity.get(callback_key)
            if last_seen is None or t.timestamp > last_seen:
                callback_last_activity[callback_key] = t.timestamp

        for r in result_events:
            task = task_by_id.get((r.operation_id, r.task_id))
            if task is None:
                continue
            callback_key = (task.operation_id, task.callback_id)
            last_seen = callback_last_activity.get(callback_key)
            if last_seen is None or r.timestamp > last_seen:
                callback_last_activity[callback_key] = r.timestamp

        for r in result_events:
            if r.status != "unknown":
                continue
            task = task_by_id.get((r.operation_id, r.task_id))
            if task is None:
                continue
            if task.command_name == "exit":
                # Exit intentionally ends callback lifecycle; missing output is expected.
                continue
            callback_key = (task.operation_id, task.callback_id)
            if r.timestamp == callback_last_activity.get(callback_key):
                r.status = "error"
                r.terminal_inferred_error = True

    def run(
        self,
        operation_id: int,
        out_dir: Path | None = None,
        analysis_timestamp: datetime | None = None,
        operation_name: str | None = None,
        output_rule: str = OUTPUT_RULE_ALL,
        arguments_rule: str = ARGUMENTS_RULE_ALL,
    ) -> dict:
        """Normalize, write outputs, and return summary metadata."""
        out_dir = out_dir or Path("out")
        events_ndjson_path = out_dir / "events.ndjson"
        bundle_path = out_dir / "bundle.json"

        if operation_name is None:
            operation_name = self.fetch_operation_name(operation_id)

        task_events, result_events = self.normalize(operation_id)
        apply_arguments_rule_to_tasks(task_events, arguments_rule)
        apply_output_rule_to_results(result_events, output_rule)
        rule_applied = normalize_output_rule(output_rule)
        args_rule_applied = normalize_arguments_rule(arguments_rule)

        all_events = [e.to_dict() for e in task_events] + [e.to_dict() for e in result_events]
        write_ndjson(all_events, events_ndjson_path)

        status_counts: dict[str, int] = {"success": 0, "error": 0, "unknown": 0}
        for e in result_events:
            status_counts[e.status] += 1

        op_slug = slugify(operation_name)
        metadata = {
            "source": "mythic",
            "operation_id": operation_id,
            "operation_name": operation_name,
            "operation_slug": op_slug,
            "mythic_endpoint": self.endpoint,
            "task_count": len(task_events),
            "result_count": len(result_events),
            "status_counts": status_counts,
            "output_rule": rule_applied,
            "arguments_rule": args_rule_applied,
            "pty_interactive_query_available": self._last_pty_interactive_query_available,
        }
        write_bundle(metadata, bundle_path, analysis_timestamp)

        return metadata
