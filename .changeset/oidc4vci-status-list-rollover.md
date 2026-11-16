---
"@better-auth/oidc4vci": patch
---

Issuance no longer stops when a status list fills up. Once random draws stop finding free indices in a list (around three quarters full), credentials go to a new list, `<listId>-2`, then `<listId>-3`, each with `statusList.size` entries, and the status list endpoint serves each of them by its `list_id`. A crowded list no longer reads every allocated index to find a free one.

`statusList.size` now accepts at most 1048576 (2^20) entries, because the status list endpoint builds the whole list on every request. A larger value throws at startup.

The `oidc4vciIssuedCredential` model gains an index on `createdAt`, which issuance reads to find the current list. Run `npx auth@latest migrate` with the built-in Kysely adapter, or run `npx auth@latest generate` and apply the schema with your ORM.
