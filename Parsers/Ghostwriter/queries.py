"""
GraphQL queries for the Ghostwriter raw exporter.
"""

GW_LOGIN_MUTATION = """
mutation Login($username: String!, $password: String!) {
  login(username: $username, password: $password) {
    token
    expires
  }
}
""".strip()

GW_QUERY_ROOT_FIELDS_QUERY = """
query QueryRootFields {
  __type(name: "query_root") {
    fields {
      name
    }
  }
}
""".strip()

GW_MUTATION_ROOT_FIELDS_QUERY = """
query MutationRootFields {
  __type(name: "mutation_root") {
    fields {
      name
    }
  }
}
""".strip()

GW_OPLOG_QUERY = """
query OplogMetadata($oplog_id: bigint!) {
  oplog(where: { id: { _eq: $oplog_id } }) {
    id
    name
    projectId
    project {
      id
      codename
      startDate
      endDate
    }
  }
}
""".strip()

GW_OPLOG_ENTRIES_QUERY = """
query OplogEntries($oplog_id: bigint!) {
  oplogEntry(
    where: { oplog: { _eq: $oplog_id } }
    order_by: { startDate: asc }
  ) {
    id
    entryIdentifier
    startDate
    endDate
    sourceIp
    destIp
    tool
    userContext
    command
    description
    output
    comments
    operatorName
    extraFields
  }
}
""".strip()
