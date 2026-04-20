"""
GraphQL queries for Mythic pull-mode parser.

Use %s for operation_id - inlined to avoid variables (can trigger PersistedQueryNotSupported).
Single-line format to match working curl requests.
"""

# Task stdout/stderr: PTY session text may aggregate here when interactive GraphQL is absent.
TASKS_QUERY = 'query { task(where: { operation_id: { _eq: %s } }) { id display_id agent_task_id callback_id callback { display_id sleep_info } command_name command { cmd payloadtype { name } } original_params status completed timestamp status_timestamp_submitted status_timestamp_processing status_timestamp_processed operation_id parent_task_id stdout stderr } }'

# Optional Hasura collection ``interactive`` (public.interactive) — exposed on Mythic versions that
# persist interactive PTY streams. Verified optional: missing root field => graceful fallback.
# Mythic 3.x / Hasura: operation-scoped via task.operation_id.
INTERACTIVE_MESSAGES_QUERY = 'query { interactive(where: { task: { operation_id: { _eq: %s } } }) { id task_id message_type data timestamp task { id operation_id agent_task_id command_name callback_id callback { display_id sleep_info } } } }'

RESPONSES_QUERY = 'query { response(where: { task: { operation_id: { _eq: %s } } }) { id task_id response_text timestamp } }'

OPERATION_QUERY = 'query { operation(where: { id: { _eq: %s } }) { id name } }'

# Minimal operation-scoped preflight that avoids depending on the optional
# `operation` table/query present in newer Mythic releases.
PREFLIGHT_TASK_QUERY = 'query { task(where: { operation_id: { _eq: %s } }, limit: 1) { id } }'

# Cross-operation parent lookup: fetch tasks by ID list with no operation filter.
# Used to resolve parent_task_id references that belong to a different operation
# (e.g. forge tasks running under a forge payload operation).
PARENT_TASKS_BY_ID_QUERY = 'query { task(where: { id: { _in: [%s] } }) { id command_name } }'
