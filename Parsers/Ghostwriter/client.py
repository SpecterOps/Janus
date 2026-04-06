"""
GraphQL client for Ghostwriter raw export.
"""

import json
import sys
import warnings

import requests

from Parsers.Ghostwriter.models import GhostwriterSchemaProbe
from Parsers.Ghostwriter.queries import (
    GW_LOGIN_MUTATION,
    GW_MUTATION_ROOT_FIELDS_QUERY,
    GW_OPLOG_ENTRIES_QUERY,
    GW_OPLOG_QUERY,
    GW_QUERY_ROOT_FIELDS_QUERY,
)


class GhostwriterSchemaError(RuntimeError):
    """Raised when the live GraphQL schema does not expose oplog export objects."""


class GhostwriterClient:
    """Small client for the Ghostwriter GraphQL endpoint."""

    GRAPHQL_PATH = "/v1/graphql"

    def __init__(
        self,
        endpoint: str,
        api_token: str | None = None,
        verify_tls: bool = True,
        debug: bool = False,
        session: requests.Session | None = None,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.api_token = api_token
        self.verify_tls = verify_tls
        self.debug = debug
        self._session = session or requests.Session()
        self._session.headers["Content-Type"] = "application/json"
        if api_token:
            self._session.headers["Authorization"] = f"Bearer {api_token}"

        if not verify_tls:
            self._session.verify = False
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    def graphql_url(self) -> str:
        if self.endpoint.endswith(self.GRAPHQL_PATH):
            return self.endpoint
        return f"{self.endpoint}{self.GRAPHQL_PATH}"

    def execute(
        self,
        query: str,
        variables: dict | None = None,
        include_auth: bool = True,
    ) -> dict:
        body = {"query": query}
        if variables:
            body["variables"] = variables

        headers = None
        if not include_auth:
            headers = {"Content-Type": "application/json"}

        if self.debug:
            print(f"DEBUG POST {self.graphql_url()}", file=sys.stderr)
            print(f"DEBUG body: {json.dumps(body)[:500]}", file=sys.stderr)

        resp = self._session.post(
            self.graphql_url(),
            json=body,
            headers=headers,
            timeout=30,
        )

        if self.debug:
            print(f"DEBUG status: {resp.status_code}", file=sys.stderr)
            print(f"DEBUG response: {resp.text[:500]}", file=sys.stderr)

        resp.raise_for_status()
        payload = resp.json()

        if payload.get("errors"):
            err_msg = "; ".join(err.get("message", str(err)) for err in payload["errors"])
            raise RuntimeError(f"GraphQL error: {err_msg}")

        if "data" not in payload:
            raise RuntimeError("GraphQL response missing 'data' key")

        return payload["data"]

    def probe_schema(self) -> GhostwriterSchemaProbe:
        query_data = self.execute(GW_QUERY_ROOT_FIELDS_QUERY)
        mutation_data = self.execute(GW_MUTATION_ROOT_FIELDS_QUERY)
        query_fields = sorted(
            field["name"]
            for field in (query_data.get("__type") or {}).get("fields") or []
            if field.get("name")
        )
        mutation_fields = sorted(
            field["name"]
            for field in (mutation_data.get("__type") or {}).get("fields") or []
            if field.get("name")
        )
        return GhostwriterSchemaProbe(
            query_fields=query_fields,
            mutation_fields=mutation_fields,
        )

    def require_oplog_access(self) -> GhostwriterSchemaProbe:
        probe = self.probe_schema()
        if not probe.oplog_access_ok:
            missing = ", ".join(probe.missing_query_fields)
            exposed = ", ".join(probe.query_fields) or "<none>"
            raise GhostwriterSchemaError(
                "Ghostwriter token/schema does not expose the expected oplog query surface. "
                f"Missing: {missing}. Exposed query_root fields: {exposed}."
            )
        return probe

    def fetch_oplog(self, oplog_id: int) -> list[dict]:
        data = self.execute(GW_OPLOG_QUERY, {"oplog_id": oplog_id})
        rows = data.get("oplog")
        if rows is None:
            raise KeyError("GraphQL response missing 'oplog' key")
        return rows

    def fetch_oplog_entries(self, oplog_id: int) -> list[dict]:
        data = self.execute(GW_OPLOG_ENTRIES_QUERY, {"oplog_id": oplog_id})
        rows = data.get("oplogEntry")
        if rows is None:
            raise KeyError("GraphQL response missing 'oplogEntry' key")
        return rows

    @classmethod
    def login(
        cls,
        endpoint: str,
        username: str,
        password: str,
        verify_tls: bool = True,
        debug: bool = False,
    ) -> tuple[str, str | None]:
        client = cls(
            endpoint=endpoint,
            api_token=None,
            verify_tls=verify_tls,
            debug=debug,
        )
        data = client.execute(
            GW_LOGIN_MUTATION,
            {"username": username, "password": password},
            include_auth=False,
        )
        login = data.get("login") or {}
        token = login.get("token")
        if not token:
            raise RuntimeError("Ghostwriter login mutation returned no token")
        return token, login.get("expires")
