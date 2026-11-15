---
"@better-auth/first-party-apps": minor
---

Add `@better-auth/first-party-apps`, the OAuth 2.0 Authorization Challenge Endpoint (draft-ietf-oauth-first-party-apps) for `oauthProvider()`. Native and command-line apps you own sign users in without a browser at `POST /oauth2/authorize-challenge`, and receive an authorization code they redeem at `/oauth2/token`. The endpoint is advertised as `authorization_challenge_endpoint` in both discovery documents.

`isFirstPartyClient` decides which clients may use the endpoint. Credentials come from methods: `passwordMethod()` checks email and password accounts, and you can add your own. When a method cannot finish, or the user has two-factor enabled, the client is sent to the browser with `redirect_to_web`. An `authorizationPolicy` can postpone issuance or ask the user to sign in again, and `challengeFirstPartyStepUp` lets the token endpoint answer `insufficient_authorization` for a step-up. The `auth_session` handle can be bound to a DPoP key (`requireDpop`), and failed responses are limited per `auth_session` and per account (`failureBudget`).

The plugin adds `firstPartyAuthSession` and `firstPartyFailureBudget` tables. Run `npx auth@latest migrate` with the built-in Kysely adapter, or run `npx auth@latest generate` and apply the schema with your ORM.
