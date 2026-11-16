---
"@better-auth/oidc4vci": minor
"@better-auth/oidc4vp": patch
---

Wallets that receive pairwise subjects can now get credentials. The credential and deferred endpoints validate the access token through the OAuth provider's `verifyResourceRequest`, which reads the user from the token's encrypted `ba_sub` claim, refuses a token whose client is disabled or whose `jti` was revoked, and enforces DPoP with the provider's proof age and nonce settings. A token that names no user, such as a `client_credentials` token, is refused with `invalid_token`.

Issued credentials change in three ways:

- A credential no longer carries `sub`. Holder binding stays in `cnf.jwk`. To include an identifier you assign, return `sub` from `resolveClaims`. The oidc4vp plugin's `VerifiedPresentation.subject` is `undefined` for these credentials.
- Each credential gets a random free index in a status list of `statusList.size` entries (131072 by default), as HAIP 1.0 section 6.1 requires, and the published list always has that many entries. A list with no free index refuses issuance with `server_error`. The status list also publishes revoked entries beyond the first 100 records of a list, which it skipped before.
- The issued-credential record no longer stores the credential.

Check your configuration:

- Register the credential audience (`credentialAudience`, by default `<baseURL>/oidc4vci/credential`) as an OAuth provider resource. The provider refuses a token for an audience it does not serve.
- Remove `allowAccessTokenInBody`, `accessTokenJwksUrl`, `accessTokenIssuer`, and `dpop.proofMaxAgeSeconds`. The provider's `dpop.proofMaxAgeSeconds` now applies. `dpop.required` and `dpop.signingAlgorithms` still narrow the provider's DPoP policy at the credential endpoints. Serve these endpoints at Better Auth's `baseURL`, because the provider checks a DPoP proof's `htu` against it.
- `accessTokenValidator` receives the provider's introspection payload, with the user id in `sub`, `client_id`, and `active`.
- A request without an access token now answers `invalid_request` instead of `invalid_token`.

The `oidc4vciIssuedCredential` model drops `credential` and gains a unique index on `statusListId` and `statusListIndex`, and the `oidc4vciStatusList` model is removed. Run `npx auth@latest migrate` with the built-in Kysely adapter, or run `npx auth@latest generate` and apply the schema with your ORM. Credentials issued before the upgrade keep their `sub`; revoke them if it must not reach verifiers.
