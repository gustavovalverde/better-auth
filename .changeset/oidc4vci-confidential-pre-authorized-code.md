---
"@better-auth/oidc4vci": patch
---

A pre-authorized code issued to a confidential client can no longer be redeemed anonymously. A token request that sends no `client_id`, `Authorization` header, or `client_assertion` now answers `invalid_client` when the code's client has a token endpoint authentication method other than `none`, so a wallet registered with a secret or a private key must authenticate to redeem its offers. Anonymous redemption (OID4VCI 1.0 section 6.1) still works for public clients, so their pre-authorized codes stay bearer secrets: anyone who holds the offer can redeem it.
