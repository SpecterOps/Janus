"""
GraphQL queries and mutations for Ghostwriter pull-mode parser.

Ghostwriter uses Hasura GraphQL Engine at /v1/graphql.
Auth: Authorization: Bearer <token>  (API key or short-lived JWT from login mutation)

Use %s for oplog_id - inlined to avoid variables (mirrors Mythic parser convention).
Single-line format to match working curl requests.
"""

# Obtain a short-lived JWT via username/password.
# POST to /v1/graphql with no Authorization header (login action is public-role).
# Returns: { login: { token: "...", expires: "..." } }
GW_LOGIN_MUTATION = 'mutation { login(username: "%s", password: "%s") { token expires } }'

# Fetch oplog metadata (name, project codename) for slug/directory naming.
GW_OPLOG_QUERY = (
    'query { oplog(where: { id: { _eq: %s } }) '
    '{ id name projectId project { id codename startDate endDate } } }'
)

# Fetch all oplog entries for a given oplog, ordered by startDate ascending.
# entry_identifier stays snake_case in Hasura (not camelCase) — always use as-is.
GW_OPLOG_ENTRIES_QUERY = (
    'query { oplogEntry('
    'where: { oplog: { _eq: %s } } '
    'order_by: { startDate: asc }'
    ') { '
    'id '
    'startDate '
    'endDate '
    'sourceIp '
    'destIp '
    'tool '
    'userContext '
    'command '
    'description '
    'output '
    'comments '
    'operatorName '
    'entry_identifier '
    'extra_fields '
    '} }'
)
