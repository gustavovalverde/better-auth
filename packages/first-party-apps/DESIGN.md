# `@better-auth/first-party-apps` design

<!-- cspell:words HMAC Zentity -->

Status: proposal. Nothing in this document is implemented yet. The code sketches show the proposed API, and none of them has been compiled or run.

Sources: Better Auth `v1.8.0-beta.10` (`0fd3a3eb7`), [draft-ietf-oauth-first-party-apps-04](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-first-party-apps-04) ("the draft" below), and design decisions C1 to C4 from the 2026-11-13 design review. The plugin lives in this fork next to `haip`, `oidc4vci`, and `oidc4vp`, and is not proposed upstream yet.

## Summary

The plugin adds the draft's Authorization Challenge Endpoint to `oauthProvider()`. A native or command-line app that your organization ships can then sign a user in without a browser redirect. The app posts the user's identifier and credentials to `POST /oauth2/authorize-challenge`, receives an authorization code, and redeems it at the token endpoint like any other code.

The plugin owns the protocol framing:

- request parsing and form encoding;
- client authentication and the first-party check;
- DPoP binding of the flow;
- the `auth_session` handle and its storage;
- abuse limits;
- error responses and HTTP statuses;
- code issuance through the provider;
- `auth_session` in the token response;
- step-up at the token endpoint.

Credential checks are pluggable methods. The plugin ships one, `passwordMethod()`, for Better Auth's email and password accounts. An app adds its own methods (for example OPAQUE or a wallet signature) through the same interface.

## Constraints

The plugin must run against the published beta.10 packages. The fork changes no upstream package, and an app installs the plugin next to the published `better-auth`, `@better-auth/core`, and `@better-auth/oauth-provider`. Every design choice below therefore uses only what beta.10 exposes.

beta.10 provides these primitives:

| Primitive | Where | Used for |
| --- | --- | --- |
| `provider.issueAuthorizationCode({ query, session })` | `oauth-provider/src/authorize.ts:1281` | Validating the request, authenticating the client, binding DPoP, checking consent and `prompt`/`max_age`, resolving `acr`/`amr`, and storing the code |
| `provider.authenticateClient({ clientId, requireCredentials, scopes })` | `oauth-provider/src/token.ts:179` | Authenticating the client on requests that do not issue a code |
| `provider.verifyDpopProof({ expectedJkt })` | `oauth-provider/src/types/index.ts:573` | Verifying the proof on requests that do not issue a code |
| `provider.challengeDpopNonce()` | `oauth-provider/src/types/index.ts:619` | Asking for a nonce before a method consumes one-time state |
| `provider.hashToken(value, type)` | `oauth-provider/src/types/index.ts:625` | Storing the `auth_session` handle the way CIBA stores `auth_req_id` |
| `createOAuthEndpoint(path, { formParams })` | `@better-auth/oauth-provider/internal` | Form-encoded bodies with RFC 6749 §3.2 cardinality and OAuth error envelopes |
| `extendOAuthProvider(ctx, { metadata })` | `@better-auth/oauth-provider` | Advertising `authorization_challenge_endpoint` |
| `adapter.incrementOne` | `core/src/db/adapter/index.ts:503` | Atomic counters and single-use state transitions |
| `getCurrentAuthEndpointContext()` | `@better-auth/core/context` | Reaching the token request's context from `customTokenResponseFields` |

beta.10 lacks four pieces, and the design works around each one. Each gap has an upstream proposal in [Upstream dependencies](#upstream-dependencies).

1. **Headless request validation (G4).** No public call validates an authorization request without issuing a code. The plugin checks what `authenticateClient` can check on the first request (client, grant type, and scopes). The provider reports any other request error when the code is issued.
2. **A token-response contribution for extensions.** `OAuthProviderExtension` has no way to add a field to the authorization-code grant's token response. The plugin composes the app's `customTokenResponseFields` at `init` (see [auth_session in the token response](#auth_session-in-the-token-response)).
3. **An `amr` input to `issueAuthorizationCode` (G4).** The provider learns `amr` only from `authenticationContext.resolve`, which receives the session. The plugin lets the app write fields onto the sessions it creates, and `resolve` reads them there.
4. **Headless second-factor verification.** The two-factor plugin verifies codes only against its signed cookie and does not export its lockout helpers. The plugin answers `redirect_to_web` for enrolled users (see [Two-factor authentication](#two-factor-authentication)).

## Public API

### Canonical usage

This sketch shows a deployment with password sign-in for its own mobile app:

```ts
import { firstPartyApps, passwordMethod } from "@better-auth/first-party-apps";
import { oauthProvider } from "@better-auth/oauth-provider";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";

const FIRST_PARTY_CLIENTS = new Set(["mobile-app"]);

export const auth = betterAuth({
  emailAndPassword: { enabled: true },
  plugins: [
    jwt(),
    oauthProvider({ loginPage: "/sign-in", consentPage: "/consent" }),
    firstPartyApps({
      isFirstPartyClient: ({ client }) => FIRST_PARTY_CLIENTS.has(client.clientId),
      methods: [passwordMethod()],
    }),
  ],
});
```

The registered client is a public native client with the `authorization_code` grant and `skip_consent: true`. An admin creates it, because dynamic registration cannot set `skip_consent`.

The app then signs the user in with two requests and redeems the code. With `dpop.nonce.required`, the first request without a nonce gets `use_dpop_nonce` and a `DPoP-Nonce` header first, as at the token endpoint.

```http
POST /api/auth/oauth2/authorize-challenge
Content-Type: application/x-www-form-urlencoded
DPoP: <proof for key K>

client_id=mobile-app&response_type=code&scope=openid%20offline_access
&login_hint=alice%40example.com&code_challenge=<S256>&code_challenge_method=S256
```

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json
Cache-Control: no-store
DPoP-Nonce: <next nonce>

{"error":"insufficient_authorization","auth_session":"<handle>","challenge_type":"password"}
```

```http
POST /api/auth/oauth2/authorize-challenge
Content-Type: application/x-www-form-urlencoded
DPoP: <proof for key K>

auth_session=<handle>&password=<password>
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{"authorization_code":"<code>"}
```

The token request carries `code`, `code_verifier`, and a proof for key K, and no `redirect_uri` (draft §6). The token response adds an `auth_session` for later step-up.

### Options

| Option | Required | Default | Meaning |
| --- | --- | --- | --- |
| `isFirstPartyClient` | yes | none | Decides whether a client may use the endpoint. See [Client opt-in](#client-opt-in). |
| `methods` | yes | none | Credential methods, in order of preference. At least one. |
| `authorizationPolicy` | no | allow | Decides, before each code, whether the user may receive it now. See [Authorization policy](#authorization-policy). |
| `session.expiresIn` | no | the app's `session.expiresIn` | Lifetime in seconds of a session the plugin creates. It bounds the grant, because the provider treats tokens whose `sid` session ended as inactive (`introspect.ts:179-186`, `:251-262`) and refuses a code whose session ended (`token.ts:2202`). |
| `session.fields` | no | none | Extra fields for a session the plugin creates. See [Session fields](#session-fields). |
| `authSession.expiresIn` | no | `600` | Lifetime in seconds of an `auth_session` whose user has not authenticated yet. |
| `authSession.maxFailures` | no | `3` | Failed method responses one `auth_session` allows before the plugin answers `redirect_to_web` and ends it (C1). |
| `authSession.maxRequests` | no | `20` | Requests one `auth_session` allows before its user authenticates (draft §9.3). |
| `failureBudget` | no | `{ maxFailures: 10, window: 900 }` | Failed responses allowed per account and method in a window of `window` seconds (C1). `false` turns it off. |
| `rateLimit` | no | `{ window: 60, max: 10 }` | Per-IP limit on the endpoint, registered as a Better Auth rate-limit rule. |
| `schema` | no | none | Model and field name overrides, merged with `mergeSchema` as in `@better-auth/ciba`. |

`init` fails when the `oauth-provider` plugin is missing, when its `grantTypes` exclude `authorization_code`, when `methods` is empty or has duplicate ids, or when `isFirstPartyClient` is not a function. It also calls each method's optional `init`.

### Client opt-in

Draft §5 and §9.1 require the authorization server to establish that a client is first-party. A client must not be able to assert it. So the opt-in is a server-side callback, and the plugin defines no client registration field:

```ts
isFirstPartyClient: (input: {
  client: SchemaClient<Scope[]>;
  ctx: GenericEndpointContext;
}) => Awaitable<boolean>;
```

The plugin calls it on every request, so a client you demote stops working mid-flow. A client it rejects gets `unauthorized_client`, and the plugin deletes that client's pending row. An authenticated row stays, because its session belongs to the user.

A registration field was considered and rejected. Extension `clientMetadata.fields` are accepted from dynamic client registration and client metadata documents, and the `validate` callback's input (`OAuthClientMetadataExtensionInput`, `types/index.ts:1009`) does not say which source registered the client. A registrant could therefore declare itself first-party. Server-owned client fields such as `skip_consent` are safe to read from the callback, because registration cannot set them.

Draft §9.8 does not recommend this flow for browser-based apps. A policy should return `false` for `user-agent-based` clients unless you have a reason to allow them.

### Methods

A method checks one kind of credential. It runs in two steps: `start` issues a challenge, and `respond` checks the client's answer. A method can answer with another challenge, so it can take several rounds, as OPAQUE does.

```ts
interface FirstPartyMethod {
  /** The `challenge_type` clients see, and part of the failure-budget key. */
  id: string;
  /** RFC 8176 values this method proves, such as ["pwd"]. */
  amr: readonly string[];
  /** Request parameters that carry a response to this method's challenge. */
  responseParameters: readonly string[];
  /** Called from the plugin's init, to fail fast on missing configuration. */
  init?: (ctx: AuthContext) => void;
  start: (input: FirstPartyMethodStartInput) => Awaitable<FirstPartyMethodStartResult | null>;
  respond: (input: FirstPartyMethodRespondInput) => Awaitable<FirstPartyMethodRespondResult>;
}

interface FirstPartyMethodStartInput {
  ctx: GenericEndpointContext;
  client: SchemaClient<Scope[]>;
  /** The `login_hint` of an initial request. Absent when `user` is set. */
  loginHint?: string;
  /** The user to authenticate again, for step-up or an elapsed `max_age`. */
  user?: User;
  /** Request parameters the plugin does not own, such as a method-specific `chain_id`. */
  params: Record<string, unknown>;
}

type FirstPartyMethodStartResult =
  | {
      type: "challenge";
      /** The account the challenge is for, or null for an unknown or not yet identified account. */
      userId: string | null;
      /** Fields added to the 403 response next to `challenge_type`. */
      challenge?: Record<string, unknown>;
      /** JSON-serializable state for `respond`. The plugin encrypts it at rest. */
      state?: unknown;
    }
  | { type: "redirect_to_web" };

interface FirstPartyMethodRespondInput {
  ctx: GenericEndpointContext;
  client: SchemaClient<Scope[]>;
  /** The `userId` that `start` returned. */
  userId: string | null;
  params: Record<string, unknown>;
  state: unknown;
}

type FirstPartyMethodRespondResult =
  | { type: "challenge"; challenge?: Record<string, unknown>; state?: unknown }
  | { type: "authenticated"; userId: string; amr?: readonly string[] }
  /** The credential verified, but the account must finish in the browser, for example to verify its email. */
  | { type: "redirect_to_web" }
  | { type: "failed" };
```

The plugin calls `start` on each method in order and uses the first result that is not `null`. A method returns `null` when it does not handle the hint, for example a wallet method given an email address, or when the given `user` has no credential for it.

A method has three obligations:

- **Timing safety for unknown accounts.** For an unknown account, `start` returns a challenge with the same fields a real account gets, and `userId: null`. `respond` then spends comparable work and returns `failed`.
- **No side effects in `respond`.** `respond` runs before the plugin has verified the client and the DPoP proof (see [Verification order](#verification-order)). It must only read the request and its own state, and may consume a one-time value it owns, such as a nonce. Anything that reaches the user, such as sending a one-time code, belongs in `start`, which runs only after verification.
- **Deliberate account disclosure.** A method that returns `redirect_to_web` from `start` for a known account reveals that the account exists, because an unknown account gets a challenge. Each method decides whether that is acceptable.

When `respond` returns `authenticated` for a different user than `start` named, the plugin treats it as `failed`. A `start` that returned `userId: null` lets `respond` name the user, which supports methods that identify the account from the response, such as a discoverable passkey.

Plugin-owned response fields are `error`, `error_description`, `auth_session`, and `challenge_type`. The plugin drops them from a method's `challenge`.

### `passwordMethod()`

`passwordMethod()` checks Better Auth email and password accounts. It takes no options and follows `/sign-in/email` (`better-auth/src/api/routes/sign-in.ts:533-578`):

- `id` is `"password"`, `amr` is `["pwd"]`, and `responseParameters` is `["password"]`.
- `start` accepts a `login_hint` that is an email address and returns `null` otherwise. It returns the same empty challenge for known and unknown addresses.
- `respond` finds the user and its `credential` account with `internalAdapter.findUserByEmail(email, { includeAccounts: true })` and checks the password with `ctx.context.password.verify`. An unknown user or a missing password hashes the submitted password first, as `/sign-in/email` does, and then fails.
- With `emailAndPassword.requireEmailVerification` and an unverified email, a correct password returns `redirect_to_web` from `respond`, so the browser can run email verification. A method returns that result only after the credential verified, so it reveals nothing to a guesser.
- `init` fails when `emailAndPassword.enabled` is off.

Usernames and phone numbers are out of scope for the first version.

### Authorization policy

`authorizationPolicy` runs before every code the plugin issues: after a fresh authentication, and when a client presents an authenticated `auth_session` again. It lets the app refuse or postpone issuance, for example when the user's assurance level does not meet `acr_values`. The provider treats `acr_values` as voluntary (OIDC Core §3.1.2.1), so strict enforcement belongs here.

```ts
authorizationPolicy?: (input: {
  ctx: GenericEndpointContext;
  client: SchemaClient<Scope[]>;
  user: User;
  request: FirstPartyAuthorizationRequest; // scope, resource, claims, acr_values, max_age, prompt
  authentication: { authTime: Date; amr: readonly string[]; fresh: boolean };
}) => Awaitable<FirstPartyAuthorizationDecision>;

type FirstPartyAuthorizationDecision =
  | void
  | { type: "insufficient_authorization"; description?: string; fields?: Record<string, unknown> }
  | { type: "reauthenticate"; description?: string }
  | { type: "redirect_to_web"; description?: string };
```

| Decision | Plugin behavior |
| --- | --- |
| nothing | Issue the code. |
| `insufficient_authorization` | Keep the user authenticated (creating the session after a fresh authentication), and answer 403 `insufficient_authorization` with `auth_session` and `fields`, without `challenge_type`. The client can resolve the condition elsewhere and present the `auth_session` again. |
| `reauthenticate` | Run a method for the user again through `start({ user })`. With no method available, answer `redirect_to_web` with the re-authentication hints. After a fresh authentication, the plugin treats it as `redirect_to_web`, so the policy cannot loop. |
| `redirect_to_web` | Answer 403 `redirect_to_web`. |

The policy can run before the plugin verifies the client and the DPoP proof, so it must not change state. The plugin removes characters that draft §5.2.2 forbids in `error_description` (anything outside `%x20-21 / %x23-5B / %x5D-7E`) from `description`.

### Session fields

The provider passes the session to `authenticationContext.resolve`, which returns the `acr` and `amr` in the ID token. The plugin lets the app store what the user proved on the sessions the plugin creates:

```ts
session: {
  fields?: (input: {
    ctx: GenericEndpointContext;
    client: SchemaClient<Scope[]>;
    user: User;
    method: string;
    amr: readonly string[];
  }) => Awaitable<Record<string, unknown>>;
}
```

The plugin passes the result to `internalAdapter.createSession(userId, false, { ...fields, expiresAt })`. It ignores `id`, `token`, `userId`, `expiresAt`, `createdAt`, and `updatedAt`. Because the session goes through the internal adapter, the provider's `session.create` hook records it as a sign-in in this request (`oauth.ts:647-652`), so `prompt=login` and `max_age` are satisfied. App database hooks on session creation also run.

An app's `resolve` then reads the fields, for example `amr: session.firstPartyAmr`. The app declares those fields in its own session schema. Once G4 adds `authentication.amr` to `issueAuthorizationCode`, the plugin can pass `amr` directly, and this hook stays for app-specific references.

### Token-endpoint step-up

Draft §6.2 lets the token endpoint refuse any request, including a refresh, with `insufficient_authorization` and an `auth_session`. The app decides when that happens, so the plugin exports a helper rather than a hook:

```ts
function challengeFirstPartyStepUp(
  ctx: GenericEndpointContext,
  input: {
    /** The client the grant was issued to. The token request must authenticate as this client. */
    clientId: string;
    userId: string;
    /** The grant's session, when it has one. The follow-up reuses it (C4). */
    sessionId?: string;
    /** The key the grant is bound to (`cnf.jkt`), when it is DPoP-bound. */
    dpopJkt?: string;
    /** The authorization request the follow-up resumes. */
    request: { scope: string; resource?: string | string[]; claims?: string; acr_values?: string; max_age?: number };
    description?: string;
    fields?: Record<string, unknown>;
  },
): Promise<void>;
```

The name follows `provider.challengeDpopNonce()`. It throws the challenge when one applies and resolves otherwise.

- **Not eligible.** For a client `isFirstPartyClient` rejects, or one not registered for the `authorization_code` grant (such as a CIBA-only agent), it resolves without side effects. The follow-up would need a code, so such a client cannot finish a step-up at the challenge endpoint. The caller then sends its own refusal, such as `interaction_required`.
- **First-party.** For a first-party client it:
  1. authenticates the request with `authenticateClient({ clientId })`, so a request that names another client fails with `invalid_client`;
  2. verifies the DPoP proof with `verifyDpopProof`, passing `expectedJkt` when `dpopJkt` is set;
  3. creates or reuses the `auth_session` (see [Step-up rows](#step-up-rows));
  4. throws HTTP 403 `insufficient_authorization` with `auth_session` and no `challenge_type` (C3). The error carries `ctx.responseHeaders`, so the `DPoP-Nonce` from verification reaches the client from a before hook too.

Call it only on a path that refuses the token request. It verifies the DPoP proof, so a request that continued to issue tokens would fail on a replayed `jti`.

A typical caller is an app's `/oauth2/token` before hook that loads the grant (a refresh token or a CIBA request) and finds that the user's assurance no longer meets the grant's `acr_values`. The CIBA grant and other extension grants can call it the same way.

### Exports

The package exports `firstPartyApps`, `passwordMethod`, `challengeFirstPartyStepUp`, `schema`, `FIRST_PARTY_APPS_ERROR_CODES`, and the types `FirstPartyAppsOptions`, `FirstPartyMethod`, the method input and result types, `FirstPartyAuthorizationDecision`, and `FirstPartyStepUpInput`. Like `haip`, it registers itself in `BetterAuthPluginRegistry` under `first-party-apps`.

## The `auth_session` model

### Fields

Model `firstPartyAuthSession`:

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | Primary key. |
| `authSession` | string, unique | The handle as `provider.hashToken(handle, "auth_session")` stores it, which follows `storeTokens` as CIBA's `authReqId` does. The raw handle is never stored. |
| `clientId` | string, indexed | References `oauthClient.clientId`, deleted with the client. |
| `userId` | string, optional, indexed | References `user.id`, deleted with the user. While the flow is pending, it is the account the method's challenge is for, which no credential has proven yet. Once the flow is authenticated, it is the proven user. |
| `sessionId` | string, optional, indexed | References `session.id`, deleted with the session. Set exactly when the flow is authenticated. |
| `ownsSession` | boolean | True when the plugin created `sessionId` for this flow. |
| `dpopJkt` | string, optional | RFC 7638 thumbprint of the key that created the row. Never changes. |
| `state` | `"pending"` or `"authenticated"` | See below. |
| `method` | string, optional | The method whose challenge is waiting for a response. |
| `methodState` | string, optional | The method's state and the original `login_hint`, as JSON encrypted with `symmetricEncrypt` and the auth secret. |
| `request` | string | The authorization request as JSON, without client credentials, `client_id`, `login_hint`, `request`, or `request_uri`. |
| `amr` | string[], optional | What the backing session proved. Feeds the policy's `authentication.amr`. |
| `failures` | number | Failed method responses since the row's user last authenticated. |
| `attempts` | number | Requests that advanced the row. It doubles as the row's version for single-use claims. |
| `expiresAt` | date, indexed | Pending rows: creation plus `authSession.expiresIn`. Authenticated rows: the backing session's `expiresAt`. |
| `createdAt`, `updatedAt` | date | |

A second model, `firstPartyFailureBudget`, holds the C1 counters: `key` (unique HMAC), `failures` (number), and `resetAt` (date).

### Handle

The handle is 32 random bytes encoded as base64url. That gives the 256 bits of entropy draft §5.3.1 recommends. The client sees only the handle, so it cannot inspect anything (§5.3.1). A database read does not reveal live handles, because the row stores only the hash.

### DPoP binding

A row is bound to the key of the proof on the request that creates it. On the initial request that comes from `verifyDpopProof()`, and at the token endpoint from the step-up helper's verification. Every later request must carry a proof for that key (§9.5.1, §9.6.1). The plugin checks the key before running a method, and the proof itself is verified exactly once per request (see [Verification order](#verification-order)). A row created without a proof stays unbound, and a later request to it must not carry a proof.

An unbound handle is a bearer credential, so it lives for one flow. When the plugin issues a code from an unbound row, it deletes the row. The token response then carries no `auth_session`, and the client cannot present the handle again. Only DPoP-bound rows outlive their first code. This keeps a stolen bearer handle from minting codes for the lifetime of the session, and satisfies the "SHOULD be bound to the device" of §5.3.1 by construction.

### States

| State | Meaning | Ends when |
| --- | --- | --- |
| `pending` | No credential has proven the user yet. A method challenge may be waiting. | It expires after `authSession.expiresIn`, it reaches `maxFailures` or `maxRequests`, or a method or the policy answers `redirect_to_web`. |
| `authenticated` | The user proved a credential, or a step-up created the row from a grant with a live session. `sessionId` names the backing session. | The backing session ends, or the row reaches `maxFailures` during re-authentication. |

An authenticated row always has a live backing session (C2). The plugin checks the session on every lookup. A row whose session ended or expired is deleted and answers `invalid_session`. The row's `expiresAt` follows the session's, which can move when the app extends a reused browser session.

Ending a row deletes its backing session only when `ownsSession` is true (C2). The plugin ends authenticated rows itself only when re-authentication reaches `maxFailures`. Deleting a session also ends the row, through the foreign key, so `revokeSession` and sign-out already end a device's `auth_session`. The first version adds no revocation endpoint.

When re-authentication succeeds on an authenticated row, the plugin creates a new session and points the row at it with `ownsSession: true`. It leaves the previous session alone. Tokens issued from that session may still be in use, and deleting it would send back-channel logout notifications for a user who did not sign out. That session expires on its own schedule, and the app's session management can still revoke it.

### Step-up rows

The step-up helper keys rows by client, user, session, and DPoP key (C4):

- When a live row exists for that combination, the helper reuses it. It writes a new handle hash, because only the hash is stored, and returns the new handle. The previous handle stops working, and the client must use the latest one (§5.3.1).
- Otherwise it creates a row. With a live `sessionId` the row is `authenticated` with `ownsSession: false`, and the follow-up issues its code on the grant's session. Without one, as for CIBA, the row is `pending` with the user set and no method, and the follow-up chooses a method for that user.

Nulls make a unique index unreliable across databases, so the lookup is a query on the indexed `sessionId` or `userId`. A race can create two rows for one grant, which is harmless.

The client's follow-up then plays out C3 and C4 as follows:

- **Authenticated step-up row.** The plugin runs the policy on the grant's session. When it passes, the plugin issues the code on that session (C4), so the ID token keeps its `sid` and `auth_time`. When the request needs a new sign-in (a `max_age` the caller set, such as `0`, or a policy `reauthenticate`), the plugin runs `start({ user })`.
- **Pending step-up row.** The plugin runs `start({ user })` for the row's user.
- **No native method.** When no method offers a challenge for the user, or a method's `start` returns `redirect_to_web`, the plugin answers 403 `redirect_to_web` with `acr_values` and `max_age: 0` (C3).

### Single-use claims

Every request that advances a row first claims it with `adapter.incrementOne` on `attempts`, guarded by the value it read. A concurrent request that read the same row gets `null` and answers `invalid_session`. This makes method state single-use whatever the method does, so two concurrent final responses cannot both issue a code. For a pending row, the plugin also refuses the claim once `attempts` reaches `authSession.maxRequests`.

### Cleanup

The plugin deletes an expired row when a client presents it. A row nobody presents again stays until something prunes it. You can prune with a scheduled `deleteMany` on `expiresAt`, which is indexed. Budget rows are overwritten when their window has passed.

## Request processing

### Encoding and parameters

The endpoint is `createOAuthEndpoint("/oauth2/authorize-challenge", { formParams: { repeatable: ["resource"] }, metadata: { noStore: true, allowedMediaTypes: ["application/x-www-form-urlencoded", "application/json"] } })`. It has the following properties:

- **Initial requests must be form-encoded.** A request without `auth_session` must use `application/x-www-form-urlencoded` (§4.1, §5.1). A JSON body answers `invalid_request`.
- **Follow-up requests may also be JSON.** A request with `auth_session` can use either encoding, because draft §5.3 lets the server define intermediate requests. Clients that send client credentials in the body should use form encoding, which is what RFC 6749 §2.3.1 defines.
- **Repeated parameters are rejected.** `formParams` turns on `cloneRequest`, which client authentication needs, and answers a repeated parameter other than `resource` with `invalid_request`.
- **No caching.** `noStore` adds `Cache-Control: no-store` to every response the handler produces, including schema errors, because `formParams` moves validation into the handler (`oauth-endpoint.ts:218-238`, `core/src/api/index.ts:100-122`). Media-type rejections happen before the handler and carry no credentials.
- **Plugin-owned parameters.** The body schema is a loose object. It types the parameters the plugin owns: `client_id`, `response_type`, `scope`, `auth_session`, `login_hint`, `code_challenge`, `code_challenge_method`, `resource`, `claims`, `acr_values`, `max_age` (coerced to a number), `prompt`, `nonce`, and `redirect_uri`. Everything else reaches methods as `params`.
- **Standard parameters reach the provider.** Authorization request parameters go to `issueAuthorizationCode`, which validates them as `/oauth2/authorize` does (§4.1). Parameters without meaning here, `response_mode`, `display`, and `state`, are dropped. A `redirect_uri` is passed on. The provider then checks that it is registered and binds the code to it, so the token request must repeat it (RFC 6749 §4.1.3).
- **App before hooks can rewrite the body.** A before hook on the path can change body values, and `applyFormParams` keeps values a hook replaced (`utils/index.ts:654-674`).

### Verification order

On the request that issues a code, `issueAuthorizationCode` authenticates the client and verifies the DPoP proof itself (`par.ts:76-121`). Two verifications in one request fail:

- A second `verifyDpopProof` rejects the proof's `jti` as replayed (`types/index.ts:567-571`).
- A second `authenticateClient` rejects a single-use client assertion.

The plugin follows one rule:

> The plugin verifies the client and the DPoP proof exactly once per request. It verifies them itself before any `start` call and before any answer other than a code. On a request that ends in a code, it leaves verification to `issueAuthorizationCode`.

`respond` and `authorizationPolicy` decide whether a request ends in a code, so they run before verification on requests that can issue one. Before they run, the plugin makes every check that consumes nothing:

1. It looks up the row and checks its state, its expiry, and, for an authenticated row, the backing session.
2. It rejects a `client_id` that differs from the row's with `invalid_client` (§5.1).
3. It resolves the client with `provider.getClient` and rejects a disabled or non-first-party client.
4. It calls `challengeDpopNonce()`, so a stale nonce is caught before a method consumes its state.
5. For a bound row, it requires a `DPoP` header whose `jwk` thumbprint (`deriveDpopJkt` from `@better-auth/core/oauth2`) equals `dpopJkt`. For an unbound row, it requires that there is no header. The thumbprint check is not verification; it lets a client that switched keys fail before its method state is spent.
6. It checks the failure budget's lock and claims the row.

Every answer other than a code then goes through `verifyDpopProof({ expectedJkt })` and `authenticateClient({ clientId: row.clientId, requireCredentials: false })` first. A caller without the key or the client's credentials therefore gets `invalid_dpop_proof` or `invalid_client` whether its response was right or wrong. The plugin does not become an oracle for credentials submitted on a stolen handle.

What remains is accepted and documented. A request with a forged proof for the right key, or a confidential client's request with a wrong secret, runs `respond` and can use up the flow's one-time state, after which the client must start again. A response checked this way still counts toward the failure limits.

Initial requests never issue a code in the first version, so they verify first and then call `start`.

### Initial request

A request without `auth_session`:

1. It must be form-encoded, with `response_type=code`. A missing `response_type` answers `invalid_request`, and another value answers `unsupported_response_type`.
2. `request_uri` answers `invalid_request` and `request` answers `request_not_supported`, as `issueAuthorizationCode` would (`par.ts:100-109`).
3. A method response parameter answers `invalid_request`. The first version needs a challenge before any credential.
4. `prompt=none` answers `login_required`. A `prompt` that needs a page (`consent`, `select_account`, `create`) answers `redirect_to_web`.
5. The plugin calls `challengeDpopNonce()` and then `authenticateClient({ clientId: body.client_id, requireCredentials: false, scopes })`, bound to the `authorization_code` grant. This authenticates a confidential client (§4.1) and rejects an unknown client, a client without the grant, and scopes the client may not request. `client_id` may be omitted when the client authenticates in a way that names it (§5.1).
6. `isFirstPartyClient` must return true, else `unauthorized_client`.
7. `verifyDpopProof()` returns the key to bind, if any.
8. The plugin calls each method's `start({ loginHint, params })` in order:
   - **A challenge.** The plugin stores a pending row and answers 403 `insufficient_authorization` with `auth_session`, `challenge_type`, and the method's fields.
   - **`redirect_to_web`, or no method handles the hint.** The plugin stores nothing and answers 403 `redirect_to_web`. The same happens without a `login_hint` when no method can start without one.

### Follow-up requests

A request with `auth_session` runs the checks from [Verification order](#verification-order), and then one of three paths:

| Row | Request | Path |
| --- | --- | --- |
| Any row with `method` set | Carries one of the method's `responseParameters` | Method response |
| Pending, no `method` (a step-up row without a session) | Anything else | Verify, then `start({ user })` for the row's user |
| Authenticated, no `method` | Anything else | Re-entry |

A pending row with `method` set and no response parameter answers `invalid_request`.

Follow-ups may carry authorization request parameters only on rows without a method in flight, which are step-up rows and authenticated rows. On other rows they answer `invalid_request`. The parameters change the stored request according to these rules:

- The parameters that describe the grant, `scope`, `resource`, `claims`, `acr_values`, and `redirect_uri`, replace the stored ones when given.
- The one-time parameters, `code_challenge`, `code_challenge_method`, `nonce`, `prompt`, and `max_age`, apply to one code. The plugin removes them from the stored request once it issues a code with them, so a PKCE challenge is never used for two codes.
- `response_type` is optional on follow-ups, and must be `code` when present. Draft Appendix A.7 shows why: its step-up request carries `auth_session`, `acr_values`, and `max_age`, but no `response_type`.

A retry after `insufficient_authorization` (no new parameters) reuses the stored request as it is, including a PKCE challenge that no code has used yet.

**Method response.** The plugin calls `method.respond`, then:

| Result | Plugin behavior |
| --- | --- |
| `challenge` | Verify, store the new state, and answer 403 `insufficient_authorization` with the new challenge. |
| `authenticated` | If the account is locked, answer as for `failed`, without counting. Otherwise check two-factor enrollment, run the policy with `fresh: true`, and continue as in [Issuing the code](#issuing-the-code). |
| `redirect_to_web` | If the account is locked, answer as for `failed`, without counting. Otherwise verify, end a pending row, and answer 403 `redirect_to_web`. |
| `failed` | Count the failure on the row and the budget, then verify. At `maxFailures` the plugin ends the row and answers 403 `redirect_to_web`. Otherwise it calls the method's `start` again with the stored hint or user and answers 400 `authentication_failed` with `auth_session` and the fresh challenge. |

A locked account (C1) still runs `respond`, so its timing does not change. Every result for it is then answered like a failure that is not counted, so a correct credential on a locked account cannot be told apart from a wrong one.

**Re-entry.** The plugin computes the request, then checks whether it needs a new sign-in:

- **`prompt=login`, or a `max_age` the session has exceeded.** The plugin verifies, then runs `start({ user })`, as the provider would otherwise refuse with `login_required` (`authorize.ts:1322-1335`).
- **Otherwise.** The plugin runs the policy with `fresh: false` and the session's `createdAt` as `authTime`, and issues on the existing session.

### Issuing the code

The plugin calls `issueAuthorizationCode` with this query:

```ts
{ ...row.request, client_id: row.clientId, dpop_jkt: row.dpopJkt, response_type: "code" }
```

The session it passes depends on the path:

- **After a fresh authentication.** The plugin first creates a session (`ownsSession: true`), with `session.fields`, and passes it.
- **On re-entry or a step-up row.** It passes the row's session.

On success the row becomes or stays `authenticated`, with `sessionId`, `amr`, `failures: 0`, and the consumed one-time parameters removed from `request`. An unbound row is deleted instead. The answer is 200 `{ "authorization_code": code }` (§5.2.1).

When `issueAuthorizationCode` throws, the plugin deletes a session it created in this request. It then maps the error:

| Provider error | Answer | Why |
| --- | --- | --- |
| `consent_required` | 403 `redirect_to_web` | Only the browser can collect consent. |
| `interaction_required` | 403 `redirect_to_web` | A `postLogin` or `signup` redirect, or a `prompt` that needs a page (`authorize.ts:1357-1370`). |
| Anything else (`invalid_client`, `invalid_dpop_proof`, `invalid_scope`, `invalid_target`, `invalid_request`, `access_denied`, `login_required`) | Unchanged | These describe the request or the client. |

After a fresh authentication, the method's one-time state is already spent, so the plugin deletes a pending row whatever the error. An authenticated row keeps its state, and the client can present it again with a corrected request.

First-party clients normally set `skip_consent`. Without it, `issueAuthorizationCode` needs stored consent and otherwise answers `consent_required` (`authorize.ts:1372-1394`), which becomes `redirect_to_web`.

### Responses

Every response the handler produces is JSON with `Cache-Control: no-store`. Responses after DPoP verification also carry the next `DPoP-Nonce`. The router answers rate-limit and media-type rejections before the handler runs, in its own format.

| Condition | HTTP status | `error` | Other fields |
| --- | --- | --- | --- |
| Code issued | 200 | none | `authorization_code` |
| A method challenge | 403 | `insufficient_authorization` | `auth_session`, `challenge_type`, method fields |
| Policy postponed issuance, or step-up at the token endpoint | 403 | `insufficient_authorization` | `auth_session`, policy `fields`, optional `error_description` |
| Wrong credential, or a locked account | 400 | `authentication_failed` | `auth_session`, `challenge_type`, fresh challenge fields |
| The browser must take over | 403 | `redirect_to_web` | `error_description`. A re-authentication also carries `acr_values` (when requested) and `max_age: 0` (C3). `auth_session` appears only when the row stays authenticated, because a pending row ends here. |
| Unknown, expired, ended, or contended `auth_session`, or a backing session that ended | 400 | `invalid_session` | |
| Client not first-party or not registered for the grant | 400 | `unauthorized_client` | |
| Client authentication failed, or `client_id` differs from the `auth_session`'s | 400, or 401 with `WWW-Authenticate` for Basic | `invalid_client` | |
| Missing or wrong DPoP proof | 400 | `invalid_dpop_proof` | |
| Stale or missing DPoP nonce | 400 | `use_dpop_nonce` | `DPoP-Nonce` header |
| Malformed request | 400 | `invalid_request`, `unsupported_response_type`, `request_not_supported`, `invalid_scope`, or `invalid_target` | |
| `prompt=none` with no usable session | 400 | `login_required` | |
| Per-IP limit | 429 | Better Auth's rate-limit body | `X-Retry-After` |

`authentication_failed` is a server-defined code, which §5.2.2 allows. It keeps a wrong credential apart from `insufficient_authorization`, which means that more steps are needed. Its 400 status is the draft's default for errors without a stated status.

The `max_age: 0` and `acr_values` hints exist because the first version cannot return a `request_uri` with `redirect_to_web` (no API pushes a request from code). The hints tell the client which parameters its browser authorization request needs so the user signs in again at that level. Without PKCE in the initial request, §5.2.2.1.1 forbids a `request_uri` anyway.

## Token endpoint

### Token request

The token endpoint redeems the code unchanged. The client omits `redirect_uri`, because the code has none, and beta.10 rejects a `redirect_uri` for such a code with `invalid_grant` (`token.ts:1953-1980`). A code bound to a key requires a proof from that key, which the provider checks before it consumes the code (`token.ts:2218-2242`).

### auth_session in the token response

Draft §6.1 lets the token response carry an `auth_session`. No supported mechanism lets an extension add a field to the built-in authorization-code grant's response. `OAuthProviderExtension` has no such contribution, and `tokenResponse` on `OAuthTokenIssueParams` serves only grants that call `issueTokens` themselves. The plugin therefore composes the app's `customTokenResponseFields` in its `init`:

```ts
const options = ctx.getPlugin("oauth-provider")!.options;
const appFields = options.customTokenResponseFields;
options.customTokenResponseFields = async (info) => {
  const fields = appFields ? await appFields(info) : {};
  if (info.grantType !== "authorization_code" || !info.verificationValue) return fields;
  const handle = await rotateAuthSessionForCode(info.verificationValue);
  return handle ? { ...fields, auth_session: handle } : fields;
};
```

`rotateAuthSessionForCode` finds the bound row for the code's `query.client_id`, `sessionId`, and `query.dpop_jkt`. It then writes a new handle hash and returns the new handle. The plugin stores only hashes, so it cannot return the handle the client already has, and draft §5.3.1 lets any response replace the handle. It reaches the database through `getCurrentAuthEndpointContext()`, because the callback receives no context.

This is safe at `init` for five reasons:

- **The assignment takes effect.** `oauthProvider()` returns its resolved options object as the plugin's `options` (`oauth.ts:234-250`, `:574`). The token endpoint reads `opts.customTokenResponseFields` from that object on every request (`token.ts:1604-1612`). `extendOAuthProvider` relies on the same object when it appends to `options.extensions` (`extensions.ts:291-306`).
- **No request sees a half-composed option.** Better Auth runs every plugin's `init` while it builds the auth context, before it serves a request.
- **The app's fields survive.** The app's function still runs first, and its fields are kept. The plugin owns only `auth_session`: it overwrites an app value of that name and logs a warning the first time it does. Standard OAuth fields stay protected by the provider.
- **No double wrapping.** The composed function is marked, and a second `init` on the same options object does not wrap it again.
- **The handle goes to the key holder.** For the authorization-code grant, the callback runs after the provider has verified the token request's DPoP proof against the code and consumed the code, and before it writes tokens (`token.ts:2218-2271`). If token creation then fails, the client has lost the old handle. It has also lost the code, so it starts again either way.

A code from the browser flow gets an `auth_session` only when a bound row exists for the same client, session, and key, which happens after a token-endpoint step-up. An unbound flow never gets one.

An after hook on `/oauth2/token` that rewrites the JSON body was considered and rejected. It would run after tokens are written, and it would have to recover the session from the issued tokens.

## Two-factor authentication

Better Auth's two-factor gate is an after hook on `/sign-in/email`, `/sign-in/username`, and `/sign-in/phone-number` (`plugins/two-factor/index.ts:433-440`), so it never runs on this endpoint. Its verification endpoints read the user from a signed cookie (`verify-two-factor.ts:22-60`), and its lockout helpers are not exported. A headless second factor would mean copying the plugin's secret decryption and lockout logic, which would drift.

The first version therefore handles two-factor like this:

1. After a method returns `authenticated` for a user with `twoFactorEnabled`, the plugin verifies the request and answers 403 `redirect_to_web`. It creates no session and issues no code.
2. The check runs only after a credential verified. The initial request and a wrong credential look the same for enrolled and other users, so enrollment is not revealed.
3. The check applies to every method. A method that proves two factors by itself, such as a user-verifying passkey, would need an exemption flag. No shipped method needs one yet.

Answering `insufficient_authorization` for a second factor, as the G6 proposal describes, needs a headless second-factor API in the two-factor plugin (see [Upstream dependencies](#upstream-dependencies)). Second-factor methods can then use the existing method interface, with the plugin calling them after the first factor instead of answering `redirect_to_web`.

## Abuse controls

Four limits apply (C1, draft §9.3):

| Limit | Scope | Default | On reaching it |
| --- | --- | --- | --- |
| `rateLimit` | IP and path, through Better Auth's rate limiter | 10 per 60 s | 429 |
| `authSession.maxRequests` | One pending `auth_session` | 20 | `invalid_session`, row deleted |
| `authSession.maxFailures` | One `auth_session` | 3 failures | 403 `redirect_to_web`, row ended |
| `failureBudget` | Account and method | 10 failures per 900 s | Silent lock |

The budget key is HMAC-SHA-256, keyed by the auth secret, over the method id and either the user id or, for an unknown account, the lowercased and trimmed `login_hint`. Unknown and known accounts therefore lock after the same number of failures, and the table holds no identifier in the clear. Only failed responses count, and a success does not reset the window. A locked account answers `authentication_failed` even for a correct credential, so a guesser cannot tell a lock from a wrong guess.

There is no per-client limit. A public `client_id` is known to everyone, so a per-client counter would let one caller block every user of the app. The per-account budget limits guessing without that effect.

`maxRequests` covers pending rows only. A re-entry on an authenticated row needs a proof from the bound key, and the per-IP limit covers it. Unbound rows never reach re-entry, because they end with their first code.

The budget accepts one residual risk: anyone can lock a known account's native sign-in for one window by sending wrong credentials. The user still reaches the browser, because the third failure in an `auth_session` answers `redirect_to_web`, and browser sign-in has its own limits.

Better Auth's rate limiter is off by default outside production. It keeps its counters in process memory unless the app configures `rateLimit.storage` or secondary storage, so the per-IP limit is per instance by default. The other limits live in the plugin's tables, so instances that share a database share them.

Draft §9.3 and §9.4 also recommend app attestation. The plugin needs nothing for it: `authenticateClient` accepts the provider's extension client-authentication strategies, such as `haip`'s `attest_jwt_client_auth`.

## Discovery

The plugin's extension contributes `authorization_challenge_endpoint: getAuthEndpointUrl(ctx, "/oauth2/authorize-challenge")` to both discovery documents (§8). The URL comes from the auth `baseURL`, so a production deployment must use an `https` base URL (§4.1). The plugin logs a warning at `init` when the base URL is `http` and not a loopback host.

## Zentity integration

Zentity keeps its credential methods and policies and replaces its endpoint framing. Today `apps/web/src/lib/auth/oidc/authorize-challenge.ts` (1,000 lines at `5b4283aa`) implements the endpoint by hand.

### What Zentity keeps

| Zentity concern | How it plugs in |
| --- | --- |
| OPAQUE three-round sign-in | An `opaque` method. `start` accepts an email hint, returns `server_public_key`, and uses the dummy registration record for unknown users. Its `responseParameters` are `opaque_login_request` (answered with a `challenge` holding `opaque_login_response` and the encrypted server login state) and `opaque_finish_request` (answered with `authenticated` or `failed`). A wallet-only user given an email answers `redirect_to_web`, which never reveals the address. |
| EIP-712 two-round sign-in | An `eip712` method. `start` accepts only an address hint and reads `chain_id` from `params`. Unknown addresses get dummy typed data. `respond` consumes the single-use nonce and verifies the signature. |
| `oauth_client.first_party` column | `isFirstPartyClient: ({ client }) => readFirstPartyColumn(client.clientId)`. The provider schema does not declare the column, so the callback reads it from the database. |
| Assurance-tier step-up | `authorizationPolicy` returns `insufficient_authorization` with the tier description when `findSatisfiedAcr(request.acr_values, tier)` fails. The authenticated `auth_session` then keeps the proven session for the retry, which replaces `resolveExistingBrowserAuth`. |
| `authentication_contexts` row and `session.authContextId` | `session.fields` creates the authentication context (`sourceKind` `authorize_challenge_opaque` or `authorize_challenge_eip712`) and returns `{ authContextId }`. The existing `authenticationContext.resolve` reads it, so `computeAcr` and `getAuthenticationStateBySessionId` leave the endpoint. |
| CIBA token step-up (`enforceCibaTokenAcr`) | It calls `challengeFirstPartyStepUp(ctx, { clientId: row.clientId, userId: row.userId, request: { scope, resource, acr_values } })` and then throws `interaction_required`. Since Z1 the CIBA row stores `acr_values` as a JSON array, so `acr_values` is `parseStoredStringArray(row.acrValues).join(" ")`. Taking the client from the CIBA row fixes the trust in `body.client_id`. |
| Stripping Zentity-hosted resources | A before hook on `/oauth2/authorize-challenge` that rewrites `ctx.body.resource`, as the `/oauth2/bc-authorize` hook does. |
| Per-IP limit | The plugin's `rateLimit` rule replaces `fpaLimiter`. The per-auth_session and per-account limits are new. |

### What changes for Zentity

These changes come with the move:

- **Clients are authenticated.** Requests now go through `authenticateClient` or `issueAuthorizationCode`.
- **No hand-written code rows.** The hand-written authorization-code row and the raw `sessions` insert are removed.
- **Two-factor applies.** Users with two-factor enabled get `redirect_to_web` instead of a code.
- **Status codes follow the draft.** `insufficient_authorization` moves from 401 to 403, `redirect_to_web` from 400 to 403, and a wrong credential from 401 `access_denied` to 400 `authentication_failed`.
- **Non-first-party clients.** They get `unauthorized_client` instead of `redirect_to_web`.
- **Encoding.** The initial request must be form-encoded. Later rounds can stay JSON.
- **No `redirect_uri` at the token endpoint.** The SDK must stop sending it for challenge codes.
- **The handle is hashed and rotates.** `auth_session` is stored hashed, and the token response returns a new handle.
- **Clients need `skip_consent`.** First-party test clients must set it.
- **The backing session lifetime changes.** It becomes `session.expiresIn` unless Zentity sets one. Today it is 10 minutes, which also caps the access tokens. Zentity should choose this value deliberately.
- **Discovery moves to the plugin.** Zentity removes `authorization_challenge_endpoint` from `discoveryMetadataExtension` in `well-known.ts`. That extension registers first, so it would keep the key and the plugin's contribution would log a collision warning.

The `auth_challenge_session` table is replaced by the plugin's `firstPartyAuthSession`. In-flight flows (10-minute lifetime) can be dropped at deploy.

### Corrections to the Z7 plan

The Z7 steps in `handoff-2026-11-15/evidence/zentity-steps.txt` were checked against the code at `5b4283aa` and beta.10. Zentity's branch has since gained Z1, Z9, Z10, and Z11 (`6c712651`). They change only an import in the challenge endpoint, but they move code in `auth-config.ts` and `step-up.ts`:

1. **`createOAuthEndpoint` import path.** It is exported from `@better-auth/oauth-provider/internal`, not the package index. `index.ts:28` exports only its types.
2. **Re-entry order (step 0(b)).** Calling `authenticateClient` and `verifyDpopProof` at the start of every intermediate round breaks the ACR retry. That round issues a code, so `issueAuthorizationCode` would verify the proof a second time and reject its `jti`. The plugin's verification rule covers every request that can end in a code.
3. **Token-response echo (step 8).** Looking up the row and echoing its handle requires storing the handle in the clear, which Zentity does today (`authChallengeSessions.authSession`). The plugin hashes it and rotates it instead.
4. **Non-first-party clients (step 3).** These get `unauthorized_client`, which is RFC 6749's code for this case and the G6 acceptance criterion, rather than `redirect_to_web`.
5. **Stale line references.** Z7's `auth-config.ts` line numbers no longer match, and they move with each slice. The code it means is the `customTokenResponseFields` echo, the `enforceCibaTokenAcr` call in `beforeCibaTokenLoadRequest`, `authenticationContext.resolve`, and the `databaseHooks.session.delete` hook. `oauthProviderApi` now comes from `@/lib/auth/oidc/oauth-provider` (Z11).
6. **Session deletion has a side effect.** The `databaseHooks.session.delete` hook denies all of the user's pending CIBA requests (`denyPendingCibaRequestsForUser(session.userId)`). The plugin deletes sessions in two cases: a session it created in a request whose issuance failed, and an owned session when re-authentication reaches `maxFailures`. Zentity should scope that hook to requests the deleted session approved, or accept the effect.
7. **Browser OPAQUE and two-factor (unverified).** Zentity's browser OPAQUE sign-in (`/sign-in/opaque/complete`) is not on the two-factor gate's path list either. Browser sign-in may also skip two-factor for OPAQUE users. This needs a check in Zentity and is outside this plugin.

## Upstream dependencies

None of these blocks the first version. Each one removes a workaround.

| Gap | Proposal | Effect on this plugin |
| --- | --- | --- |
| G4 validation | `provider.validateAuthorizationRequest({ query })` | Validate the whole request on the initial request, before any credential is spent. |
| G4 `amr` | `authentication.amr` on `IssueAuthorizationCodeParams` | Pass the method's `amr` without session fields. |
| Token response | An extension-level token-response contributor for the authorization-code grant | Replace the `customTokenResponseFields` composition. |
| PAR from code | A provider method that pushes a request and returns `request_uri` | Return `request_uri` with `redirect_to_web` when the initial request had PKCE (§5.2.2.1.1). |
| Headless second factor | A server API in the two-factor plugin that verifies a code for a user, with its attempt cap and lockout | Answer `insufficient_authorization` for a second factor. |
| `error_description` characters | Strip characters RFC 6749 §5.2 forbids from provider error descriptions. A zod pattern failure reaches the description with its regular expression, backslashes included. | Plugin responses that pass provider errors through stay conformant. |

## Package layout

The package follows `packages/haip`:

| Path | Contents |
| --- | --- |
| `package.json` | `@better-auth/first-party-apps`, version `1.8.0-beta.10`. Peers: `better-auth`, `@better-auth/core`, `@better-auth/oauth-provider`, `@better-auth/utils`, `better-call`. Dependencies: `jose` (protected-header decoding), `zod`. |
| `tsdown.config.ts`, `tsconfig.json`, `vitest.config.ts` | As in `haip`, with references to `better-auth`, `core`, and `oauth-provider`. |
| `src/index.ts` | `firstPartyApps`, the `init` checks, the extension, the token-response composition, and the exports. |
| `src/endpoint.ts` | The challenge endpoint: parsing, verification order, paths, issuance, and responses. |
| `src/auth-session.ts` | Row creation, lookup with liveness, claims, counters, rotation, and ending. |
| `src/failure-budget.ts` | The C1 budget. |
| `src/step-up.ts` | `challengeFirstPartyStepUp`. |
| `src/password.ts` | `passwordMethod`. |
| `src/schema.ts`, `src/types.ts`, `src/error-codes.ts` | Schema, public types, and error codes. |
| `test/` | Tests on `getTestInstance()`. |

Zentity vendors it like the other plugins. The package is added to `PACKAGES` in `apps/web/scripts/rebuild-vendor.sh`, and its tarball, commit, and SHA-256 go in `apps/web/vendor/README.md`.

## Test plan

Tests use `getTestInstance()` with `jwt()`, `oauthProvider()`, and `firstPartyApps()`. They use `passwordMethod()` and a recording test method. The test method has a two-step challenge, counts `start` and `respond` calls, and can be told to fail. Each item names the behavior to prove.

**Setup and discovery**

- `init` fails without `oauth-provider`, with `authorization_code` disabled, with no methods, with duplicate method ids, and without `isFirstPartyClient`. `passwordMethod()` fails without `emailAndPassword.enabled`.
- Discovery advertises `authorization_challenge_endpoint` when the plugin is registered, and not otherwise.

**Encoding**

- A JSON initial request answers `invalid_request`, and a form-encoded one is accepted.
- A JSON follow-up is accepted.
- A repeated parameter answers `invalid_request`, and a repeated `resource` is accepted.
- Every response, including a schema error, carries `Cache-Control: no-store`.

**Initial request**

- A missing `response_type` answers `invalid_request`, and `response_type=token` answers `unsupported_response_type`.
- `request_uri` and `request` are rejected with the provider's codes.
- A method response parameter answers `invalid_request`.
- `prompt=none` answers `login_required`, and `prompt=consent` answers `redirect_to_web`.

**Clients**

- An unknown client answers `invalid_client`, and so does a confidential client without credentials.
- A client without the `authorization_code` grant answers `unauthorized_client`.
- A client the policy rejects answers `unauthorized_client`, and no row is created.
- A follow-up that names another client answers `invalid_client`, and one that omits `client_id` is accepted.
- A client the policy starts rejecting mid-flow answers `unauthorized_client`.
- A confidential client with a wrong secret on the initial request never reaches `start`.

**Password flow**

- Hint, then password, then code, then token with PKCE and no `redirect_uri` succeeds.
- A token request with `redirect_uri` answers `invalid_grant`.
- An unknown email gets a challenge with the same fields as a known one.
- A wrong password answers 400 `authentication_failed` with `auth_session`.
- The third failure answers 403 `redirect_to_web` and deletes the row.
- An unverified email with `requireEmailVerification` answers `redirect_to_web` after a correct password.

**DPoP**

- The initial proof binds the row.
- On a bound row, a follow-up without a proof or with another key answers `invalid_dpop_proof`, and the test method's `respond` is not called.
- A proof on an unbound row answers `invalid_dpop_proof`.
- With nonces required, a stale nonce answers `use_dpop_nonce` before `respond` runs, and the retry redeems the same method state.
- The final response issues a code with one proof, with no replay error.
- A token request with another key fails.

**Verification order**

- For a caller with the right `jwk` but a forged signature, correct and wrong responses both answer `invalid_dpop_proof`.
- `start` is never called before client authentication and DPoP verification.

**Handles and rows**

- The handle is at least 43 base64url characters, and the stored value differs from it.
- Unknown and expired handles answer `invalid_session`.
- Two concurrent final responses issue exactly one code.
- `maxRequests` ends a pending row.

**Liveness and ownership (C2)**

- After the backing session is deleted, the handle answers `invalid_session`, and the row is gone.
- Reaching `maxFailures` during re-authentication deletes an owned session and keeps a reused one.

**Two-factor**

- A user with `twoFactorEnabled` gets 403 `redirect_to_web` after a correct password, with no session row and no code.
- The initial response and a wrong-password response are identical for enrolled and other users.

**Failure budget (C1)**

- Ten failures across `auth_session`s lock the account. A correct password then answers `authentication_failed`.
- The lock ends after the window.
- An unknown email locks after the same number of failures.
- No budget row contains the email or the user id.

**Policy**

- `insufficient_authorization` answers 403 with `auth_session` and leaves an authenticated row. A retry after the condition changes issues a code on the same session, with the same `sid` and `auth_time` in the ID token.
- `reauthenticate` challenges the user again, and success creates a new session.
- `redirect_to_web` answers 403.
- Forbidden characters are removed from `description`.

**Issuance errors**

- A client without `skip_consent` and without stored consent answers `redirect_to_web`, and the created session is deleted.
- An unknown resource answers `invalid_target`, and the created session is deleted.

**Re-entry (Appendix A.7)**

- A bound authenticated row plus `acr_values` and `max_age=0`, without `response_type`, challenges the user again.
- After a code is issued, re-entry without a new `code_challenge` fails for a client that requires PKCE.
- An unbound row is deleted after its code.

**Token response**

- A bound flow's token response carries a new `auth_session`. The old handle stops working, and the new one works.
- The app's `customTokenResponseFields` fields are kept, and its `auth_session` is overwritten with one warning.
- An unbound flow, and a browser code with no row, get no `auth_session`.
- Building two auth instances from one options object does not wrap twice.

**Step-up helper (C3, C4)**

- Called from a refresh-token before hook for a first-party client, it answers 403 `insufficient_authorization` with `auth_session`, `no-store`, and `DPoP-Nonce`.
- For a non-first-party client, and for one without the `authorization_code` grant, it resolves, and the caller's error is sent.
- A request authenticated as another client answers `invalid_client`.
- A proof from a key other than `dpopJkt` answers `invalid_dpop_proof`.
- A second call for the same client, user, session, and key leaves one row with a new handle.
- A follow-up for a user with no native method answers `redirect_to_web` with `acr_values` and `max_age: 0`.
- A follow-up whose policy now passes issues a code on the grant's session.

**Session fields and types**

- `session.fields` values are stored on the session and reach `authenticationContext.resolve`, and `amr` appears in the ID token.
- A public-types test covers the options, the method interface and results, the policy decision, and the helper input with `expectTypeOf`.
- With rate limiting enabled, the endpoint answers 429 after `rateLimit.max` requests from one IP.

Zentity's own tests come from Z7, adapted to this plugin:

- `authorize-challenge.integration.test.ts` with form-encoded round 1, 403 statuses, and `skip_consent` fixtures;
- the step-up suites, DPoP nonce, UserInfo disclosure, and well-known suites;
- the OPAQUE and EIP-712 hint rules;
- the ACR retry keeping `sid` and `auth_time`;
- the CIBA client-mismatch case;
- the SDK's form round 1 and missing `redirect_uri`;
- `apps/mcp` tests for the SDK's installed client.

## Draft-04 conformance check

| Section | Requirement | Design |
| --- | --- | --- |
| §4.1 | Form-encoded POST, UTF-8 | Initial requests form-only. Follow-ups form or JSON (§5.3). |
| §4.1 | `https` endpoint | Built from `baseURL`, with a warning for non-loopback `http`. |
| §4.1 | Client authentication where the token endpoint requires it | `authenticateClient` or `issueAuthorizationCode`, which both require a confidential client's credentials. |
| §4.1 | Accept authorization request parameters and extensions | Passed to `issueAuthorizationCode`. Meaningless ones are dropped. |
| §4.1, §8 | Advertise `authorization_challenge_endpoint` | Extension metadata. |
| §4.2, §6.2 | Token endpoint may answer `insufficient_authorization` | `challengeFirstPartyStepUp`. |
| §5, §9.1 | Server verifies first-partyness | `isFirstPartyClient` on every request, with no registration field. |
| §5.1 | `client_id` rules, mismatch rejected | Initial: client authentication names the client. Follow-up: the row's client, with mismatch answering `invalid_client`. |
| §5.1 | `response_type=code` required | Required on initial requests, following the normative text, although Appendix B.3 omits it there too. Optional on follow-ups, because Appendix B.3 and A.7 omit it. |
| §5.2, §5.2.1 | Code or error. 200 JSON with `authorization_code`. | As specified, with `no-store`. |
| §5.2.2 | 400 default. ASCII-restricted `error_description`. JSON top-level fields, numbers as numbers. | As specified, with app and method descriptions sanitized and provider pass-through noted upstream. |
| §5.2.2.1 | `invalid_session`. 403 `insufficient_authorization` and `redirect_to_web`. | As specified. |
| §5.2.2.1.1 | `request_uri` only with PKCE. Redirect flows follow RFC 9700, including `iss`. | No `request_uri` in the first version, with re-authentication hints instead. The browser flow is the provider's `/oauth2/authorize`, which returns `iss` (RFC 9207). |
| §5.3 | Server-defined intermediate requests | Method challenges and `responseParameters`. |
| §5.3.1 | Opaque handle, unique, at least 256 bits, may change in any response, SHOULD be device-bound | 32 random bytes, stored hashed, DPoP-bound, rotated in the token response. Unbound handles last one flow. |
| §6 | Token request without `redirect_uri` | Provider behavior for headless codes. |
| §6.1 | `auth_session` in the token response | Composed `customTokenResponseFields`, for bound rows. |
| §7 | Step-up from a resource server error | Re-entry with `acr_values` and `max_age`, or a new initial request. Policy decides. |
| §9.2 | Server may require the browser at any stage | Method, policy, and plugin `redirect_to_web`. |
| §9.3 | Rate-limit per `auth_session`. Credential stuffing. | `maxRequests` (pending rows), `maxFailures`, the account budget, and the IP limit. Authenticated rows rely on DPoP binding and the IP limit. |
| §9.4 | Client impersonation | Extension client-authentication strategies, such as attestation. |
| §9.5, §9.5.1 | DPoP binding of code and tokens. Same key on every request and at the token endpoint. | Row binding, the thumbprint check, provider verification, and the code's `dpop_jkt`. |
| §9.6.1 | Check the key and verify the proof whenever `auth_session` is sent | Every request is verified once, by the plugin or by `issueAuthorizationCode`. |
| §9.6.2 | Lifetime at the server's discretion | Pending rows by `authSession.expiresIn`, authenticated rows by their session. |
| §9.8 | Not recommended for browser apps | Documented for `isFirstPartyClient`. |

The check against §4 to §9 changed the design in seven places:

1. Follow-ups may carry authorization request parameters without `response_type`, because Appendix A.7 does.
2. One-time parameters are not reused across codes.
3. `error_description` values are sanitized.
4. The plugin warns about a non-`https` base URL.
5. The `isFirstPartyClient` guidance covers §9.8.
6. A `redirect_to_web` response states when it carries `auth_session` (§5.2.2).
7. The scope of the per-session request limit is stated, with authenticated rows relying on DPoP binding (§9.3).

## Decisions requested

1. **Unbound handles last one flow.** An `auth_session` without DPoP binding is deleted when its code is issued, so it never appears in a token response and cannot be presented again. The alternative keeps bearer handles alive with the session.
2. **No credential on the initial request.** Single-request flows such as draft Appendix A.3 (hint and one-time code together) wait for G4 or a later version.
3. **`unauthorized_client` for non-first-party clients**, instead of `redirect_to_web`.
4. **The failure budget does not reset on success.** This reads C1 literally ("only failures count"). Resetting on success, as the two-factor lockout does, is friendlier to users who mistype often.
5. **The previous owned session is kept after re-authentication**, rather than deleted.
6. **The plugin's sessions default to the app's `session.expiresIn`.**
