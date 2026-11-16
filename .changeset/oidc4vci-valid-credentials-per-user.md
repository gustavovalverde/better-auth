---
"@better-auth/oidc4vci": patch
---

Add `maxValidCredentialsPerUser`, which limits how many valid credentials of one configuration a user may hold, 100 by default. A credential counts until it is revoked or `credentialExpiresInSeconds` after its issuance. A credential request beyond the limit answers `credential_request_denied`, so one user can no longer create status list entries and issued-credential records without bound by reusing an access token with fresh nonces.
