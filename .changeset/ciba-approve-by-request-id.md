---
"@better-auth/ciba": patch
---

`POST /ciba/authorize` and `POST /ciba/reject` now accept `request_id` (the request's id) as an alternative to `auth_req_id`. A first-party, session-authenticated UI can list a user's own pending requests and approve or reject one by id, without holding the raw `auth_req_id` (only its hash is stored). Ownership is still enforced by the session. Push delivery continues to require `auth_req_id`, since it echoes the raw token back to the client.
