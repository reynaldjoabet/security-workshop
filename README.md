# security-workshop
## About OAuth 2.0 and 2.1
[OAuth 2.0](https://connect2id.com/learn/oauth-2) is an authorisation framework 
for a third-party application to obtain limited access to an HTTP service, 
either on behalf of a resource owner (the user), or by allowing the third-party 
application to obtain access on its own behalf.

OAuth 2.0 is specified in [RFC 6749](http://tools.ietf.org/html/rfc6749) and 
its companion specifications.

[OAuth 2.1](https://connect2id.com/learn/oauth-2-1) is a [working 
draft](https://tools.ietf.org/html/draft-ietf-oauth-v2-1-09) that rolls the 
original OAuth 2.0 RFC and best practises established over the years into a 
simpler, safer and more streamlined authorisation framework.


## About OpenID Connect 1.0
[OpenID Connect 1.0](https://connect2id.com/learn/openid-connect) is a simple 
identity layer on top of the OAuth 2.0 framework. Relying parties (clients) 
verify the identity of the user based on the authentication performed by an 
authorisation server, as well as to obtain basic profile information about the 
user in an interoperable and REST-like manner.

OpenID Connect enables clients of all types, including Web-based, mobile, and 
JavaScript clients, to request and receive information about authenticated 
sessions and end-users. The specification suite is extensible, allowing 
optional encryption of identity data, discovery of OpenID Providers, and 
session management.

Go to the [OpenID Connect specifications](http://openid.net/connect/) for more 
details.

## Standards and drafts
* The OAuth 2.0 Authorization Framework (RFC 6749)

* The OAuth 2.1 Authorization Framework (draft-ietf-oauth-v2-1-11)

* The OAuth 2.0 Authorization Framework: Bearer Token Usage (RFC 6750)

* OAuth 2.0 Token Introspection (RFC 7662)

* OAuth 2.0 Token Revocation (RFC 7009)

* OAuth 2.0 Authorization Server Metadata (RFC 8414)

* OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)

* OAuth 2.0 Dynamic Client Registration Management Protocol (RFC 7592)

* Assertion Framework for OAuth 2.0 Client Authentication and Authorization
  Grants (RFC 7521)

* JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
  Authorization Grants (RFC 7523)

* SAML 2.0 Profile for OAuth 2.0 Client Authentication and Authorization
  Grants (RFC 7522)

* Proof Key for Code Exchange by OAuth Public Clients (RFC 7636)

* Authentication Method Reference Values (RFC 8176)

* OAuth 2.0 Authorization Server Metadata (RFC 8414)

* OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access
  Tokens (RFC 8705)

* OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer
  (DPoP) (RFC 9449)

* Resource Indicators for OAuth 2.0 (RFC 8707)

* OAuth 2.0 Device Authorization Grant (RFC 8628)

* OAuth 2.0 Token Exchange (RFC 8693)

* OAuth 2.0 Incremental Authorization (draft-ietf-oauth-incremental-authz-04)

* The OAuth 2.0 Authorization Framework: JWT Secured Authorization Request 
  (JAR) (RFC 9101)

* OAuth 2.0 Pushed Authorization Requests (RFC 9126)

* OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)

* OAuth 2.0 Rich Authorization Requests (RFC 9396)

* OAuth 2.0 Step Up Authentication Challenge Protocol (RFC 9470)

* OpenID Connect Core 1.0 (2014-02-25)

* OpenID Connect Core Unmet Authentication Requirements 1.0 (2019-05-08)

* OpenID Connect Discovery 1.0 (2014-02-25)

* OpenID Connect Dynamic Registration 1.0 (2014-02-25)

* OpenID Connect Session Management 1.0 (2022-09-12)

* OpenID Connect RP-Initiated Logout 1.0 (2022-09-12)

* OpenID Connect Front-Channel Logout 1.0 (2022-09-12)

* OpenID Connect Back-Channel Logout 1.0 (2023-12-15)

* OpenID Connect Native SSO for Mobile Apps 1.0 - draft 07

* OpenID Connect Client Initiated Backchannel Authentication (CIBA) Flow -
  Core 1.0

* OpenID Connect Extended Authentication Profile (EAP) ACR Values 1.0 -
  draft 00

* OpenID Connect for Identity Assurance 1.0 - draft 12

* OpenID Federation 1.0 - draft 29

* Initiating User Registration via OpenID Connect 1.0 (2022-12-02)

* OAuth 2.0 Multiple Response Type Encoding Practices 1.0 (2014-02-25)

* Financial Services – Financial API - Part 1: Read Only API Security
  Profile (2021-03-12)

* Financial Services – Financial API - Part 2: Read and Write API Security
  Profile (2021-03-12)

* Financial-grade API: JWT Secured Authorization Response Mode for OAuth
  2.0 (JARM) (2018-10-17)

## OAuth Related
- device
- dpop
- jarm
- pkce
- rar
- token
- token exchange
- token introspection
- token revocation
- mutual tls

## Open Banking and PSD2
- UK Open Banking (OBIE)
- European PSD2 / Berlin Group
- North American FDX (Financial Data Exchange)
- Australian CDR (Consumer Data Right)

## Decentralized Identity & Wallets (eIDAS 2.0)
- OIDC4VP (OpenID for Verifiable Presentations) & OIDC4VCI (Verifiable Credential Issuance): Instead of the fintech app redirecting the user to the Bank's centralized IDP, the bank issues a Verifiable Credential to a digital wallet on the user's phone. The fintech app then directly requests a presentation from the wallet.
- SIOPv2 (Self-Issued OpenID Provider): Allows the user's mobile wallet to act as its own OpenID Provider without an intermediate server.

`Native SSO for Mobile Apps` (device_sso): While poking around It allows a family of apps from the same publisher to share SSO state on a mobile device without repeatedly bouncing the user through the system browser.


## OpenID Connect
OIDC is built on top of OAuth 2.0 by reusing its delegation machinery to deliver an authentication 
### How the reuse actually works
The OIDC Authorization Code flow is literally the OAuth 2.0 Authorization Code flow with extra parameters:
```http
GET /authorize?
    response_type=code            <-- pure OAuth 2.0
    &client_id=app
    &redirect_uri=https://app/cb
    &scope=openid profile email   <-- "openid" triggers OIDC
    &state=xyz
    &nonce=n-0S6_WzA2Mj            <-- OIDC-only: replay defense
    &code_challenge=...            <-- OAuth 2.0 PKCE
    &code_challenge_method=S256
```    
The user authenticates at the OP, consents, gets redirected back with `code`. The client exchanges the `code` at `/token`:

```sh
POST /token
    grant_type=authorization_code
    code=...
    code_verifier=...
    client_id=app
```
The response is a standard OAuth 2.0 token response — but if `openid` was in scope, it now contains an `id_token` field next to `access_token`:
```json
{
  "access_token": "...",        // OAuth 2.0 — for the resource API
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJ..."          // OIDC — for the client, about the user
}
```
The client validates the ID token:
- Signature against the OP's JWKS
- `iss` matches the configured OP
- `aud` contains the client's client_id
- `exp` not past, `iat` reasonable
- `nonce` matches what the client sent
- (optional) `acr` / `amr` / `auth_time` meet policy
Only after those checks does the client treat `sub` as "this is the logged-in user."

`OAuth 2.0 is a delegation framework that produces tokens. OpenID Connect uses that exact flow to deliver a different kind of token — a signed ID token whose audience is the client and whose purpose is to assert who authenticated.`


`OAuth 2.0 is the transport. OIDC is a payload — an authentication assertion — delivered over that transport.`

### OIDC reuses two things from OAuth 2.0
### The wire protocol (the flow itself)
- Same endpoints: ` /authorize`, ` /token`
- Same redirect dance, same code → token exchange
- Same client authentication methods (`client_secret_basic`, `private_key_jwt`, `mTLS`…)
- Same security extensions plug in unchanged (PKCE, PAR, DPoP, JAR, mTLS-bound tokens)

### The trust & consent model
- Pre-registered client with known `redirect_uri`
- User-present consent at the AS
- `state`, `scopes`, `error` codes, `response_type` — all OAuth 2.0 mechanics

### What OIDC adds on top
It does not invent a new flow. It adds content to the existing one:
- A new scope value: openid — this is the switch that turns an OAuth flow into an OIDC flow.
- A new response artifact: the ID token (signed JWT about the user, audience = client).
- A new parameter: nonce (replay defense for the ID token).
- A new endpoint: `/userinfo` (called with the OAuth access token).
- Discovery + JWKS conventions so the client can verify the ID token.

### ID token validation (OIDC §3.1.3.7)
- Signature verifies against the OP's JWKS (iss-derived).
- `iss` exactly matches the OP you talked to.
- `aud` contains your `client_id` (and rejects unexpected extra audiences unless azp is set correctly).
- `exp` is in the future, `iat` is sane.
- `nonce` matches the one you sent in the auth request.
- If you asked for `acr` / `max_age`, check `acr` and `auth_time`.
- `at_hash` matches the access token (if present), `c_hash` matches the code (if present in hybrid).

## Why OIDC Alone Doesn't Scale
Assumes a pre-existing trust relationship between exactly two parties:
- The Relying Party (RP / client) was registered at the OpenID Provider (OP) ahead of time.
- Either manually (admin pastes `client_id` / `client_secret`) or via Dynamic Client Registration (RFC 7591) on a single OP.
- The RP knows the OP's issuer URL and its JWKS by configuration.

That's fine for "Login with Google" — there's one Google, you registered once, done.

It breaks the moment you have:
- `1,000` banks and `500` fintechs that all need to talk to each other (Open Banking).
- `27` EU member states with national eID providers federating into a single wallet ecosystem (eIDAS / EUDI).
- `Thousands` of universities sharing research infra (eduGAIN-style trust).

You can't have every RP manually register at every OP. That's an O(N×M) problem.

## OpenID Federation (still draft, ~draft 29)
Solves the O(N×M) problem the same way PKI / CAs solve certificate trust, but for OIDC entities:
- Every entity (RP, OP, intermediate, trust anchor) publishes a signed Entity Statement at `/.well-known/openid-federation`.
- Statements form a trust chain from any entity up to a Trust Anchor that everyone agrees on (a regulator, a federation operator, a government).
- Trust Anchor's keys are configured out-of-band (one-time, like a root CA).
- Intermediate "Trust Marks" / policies can clamp what's allowed (e.g. "all RPs in this federation MUST use `private_key_jwt` and PS256").
- A new RP that's never seen a particular OP can — at runtime — resolve a trust chain, verify all signatures up to a known anchor, derive the OP's effective metadata under the federation's policies, and proceed.
- Same in reverse: the OP doesn't need pre-registration of the RP. It walks the chain, sees the RP is endorsed by the trust anchor, accepts the request.

## What problem DCR solves
Without it, every new OAuth/OIDC client has to be registered manually at the authorization server: an admin logs into an admin console (or hits an internal API), creates a client record, copies out a `client_id` / `client_secret`, and pastes them into the app's config.

That's fine for two or three clients. It falls over when:
- A SaaS product has thousands of customer instances, each needing its own client.
- A mobile app installs onto millions of devices, each instance acting as its own client.
- An ecosystem (Open Banking, GAIN, eIDAS) requires every participant to register at every provider.
- A CI pipeline spins up ephemeral clients per environment.
- Dynamic Client Registration (DCR) standardizes a protocol the client uses to register itself programmatically — RFC 7591 defines it, RFC 7592 adds management (read/update/delete).

`Because OIDC didn't fork OAuth — it inherits OAuth's flow as-is, and OAuth was deliberately designed as an extension framework, not a closed protocol. So any new spec that extends OAuth's endpoints or messages plugs into OIDC for free, with no OIDC change required.`

OIDC reuses OAuth at three places where every OAuth extension also hooks in:

| OAuth surface          | What extensions do here | Why OIDC inherits |
|------------------------|-------------------------|-------------------|
| /authorize request     | Add parameters (code_challenge, request_uri, dpop_jkt, authorization_details, resource, acr_values…) | An OIDC auth request is an OAuth auth request — extra params just pass through |
| /token request & response | Add new grant types, new token-binding semantics, new response fields | OIDC piggybacks on the same token endpoint; the response just gains an id_token field next to whatever the extension added |
| Client authentication  | New auth methods (private_key_jwt, tls_client_auth, self_signed_tls_client_auth) | OIDC has no client-auth mechanism of its own — it uses OAuth's put in a table |

## The mechanism that makes it work — extension points
OAuth 2.0 baked four extension points into the spec, and OIDC respects all of them:
- Custom `response_type` values — code, token, plus anything new (`id_token`, code `id_token`, etc. were added by OIDC using exactly this slot).
- Custom `grant_type` URIs — anything namespaced by URI (`urn:ietf:params:oauth:grant-type:device_code`, `urn:openid:params:grant-type:ciba`, `urn:ietf:params:oauth:grant-type:token-exchange`).
- Custom request/response parameters — the spec explicitly says unknown parameters MUST be ignored, so adding nonce, claims, `code_challenge`, `dpop_jkt`, `authorization_details` doesn't break anything.
- Custom `token_type` — `Bearer`, `DPoP`, MAC (deprecated). OIDC issues `Bearer` by default; `DPoP` just swaps it.

Every one of these is an OAuth 2.0 extension RFC — none of them mention OIDC in their core definition — yet OIDC deployments use all of them daily.

### Authorization-request extensions

| Extension | RFC | What it adds | How OIDC uses it |
|-----------|-----|--------------|------------------|
| PKCE | 7636 | code_challenge / code_verifier to defend code interception | Mandatory for OIDC public clients; recommended for all |
| PAR | 9126 | Push the auth request back-channel, get a request_uri | OIDC RP pushes the whole OIDC request, including nonce and claims |
| JAR | 9101 | Sign/encrypt the auth request as a JWT | OIDC's request / request_uri parameters use this directly |
| Resource Indicators | 8707 | `resource= parameter` to scope tokens to one API | OIDC RP requests an access token bound to a specific RS |
| Issuer ID | 9207 | iss parameter on redirect, defends IdP mix-up | Critical for multi-OP OIDC clients |
| RAR | 9396 | authorization_details for fine-grained consent | OIDC consent UI shows the RAR, AS embeds it in tokens |
| Step-up auth | 9470 | `WWW-Authenticate: insufficient_user_authentication` | RS demands higher ACR; client triggers OIDC re-auth with `acr_values` |

### Token-endpoint extensions
| Extension | RFC | What it adds | OIDC inherits |
|-----------|-----|--------------|---------------|
| JWT bearer grant | 7523 | Trade a JWT for tokens; basis for `private_key_jwt` client auth | OIDC RPs authenticate this way |
| SAML bearer grant | 7522 | Trade a SAML assertion for tokens | Used in SAML→OIDC bridges |
| Device code | 8628 | `urn:ietf:params:oauth:grant-type:device_code` | OIDC works on TVs / CLIs through this exact grant |
| Token Exchange | 8693 | Delegate / impersonate via subject_token + actor_token | OIDC ID tokens can be subject tokens; chains identity across services |
| CIBA | OIDC-CIBA | `urn:openid:params:grant-type:ciba` | OIDC-defined, but uses OAuth's grant-type extension slot — same mechanism |

### Token-binding & token-format extensions
| Extension | RFC | What it adds | OIDC inherits |
|-----------|-----|--------------|---------------|
| mTLS | 8705 | Client cert auth + cert-bound access tokens | OIDC RPs authenticate via mTLS; ID tokens are unaffected, access tokens get a cnf.x5t#S256 |
| DPoP | 9449 | Proof-of-possession via per-request signed JWT | Same — OIDC tokens (the access token, not the ID token) become DPoP-bound |
| JWT access tokens | 9068 | Standardized at+jwt profile for access tokens | OIDC deployments use this for stateless RS validation |

### Operational extensions
| Extension | RFC | What it adds | OIDC inherits |
|-----------|-----|--------------|---------------|
| Token Introspection | 7662 | /introspect endpoint for opaque tokens | RS validates OIDC-issued access tokens this way |
| Token Revocation | 7009 | /revoke endpoint | OIDC RP logout calls this on the refresh token |
| AS Metadata | 8414 | /.well-known/oauth-authorization-server | OIDC's `/.well-known/openid-configuration` is the same shape, with extra fields |
| Dynamic Client Registration | 7591 / 7592 | POST /register | OIDC adds OIDC-specific metadata fields; same protocol |

`A FAPI 2.0 OIDC login uses all of these simultaneously, each one an independent OAuth extension:`

```sh
authorize
  └── JAR (signed request object)            ← RFC 9101
       └── PAR (pushed back-channel)          ← RFC 9126
            └── PKCE (code_challenge)         ← RFC 7636
                 └── DPoP (dpop_jkt binding)  ← RFC 9449
                      └── private_key_jwt     ← RFC 7523
                           on a TLS-mutual-authenticated channel
                                              ← RFC 8705
                           returning a JARM signed response
                                              ← (FAPI / OIDF)
                            yielding both:
                              ─ id_token   (OIDC)
                              ─ access_token bound to DPoP key (OAuth ext)

```

### nonce— replay defense for the ID token
A random value the client generates and includes in the auth request. The OP echoes it back inside the ID token. The client compares.
Auth request:
```http
GET /authorize?
    response_type=code
    &client_id=app
    &scope=openid profile
    &nonce=n-0S6_WzA2Mj                ← client-generated
    &state=xyz
    ...
```    
ID token claims (later):
```json
{
  "iss": "...",
  "aud": "app",
  "nonce": "n-0S6_WzA2Mj",             ← must match what client sent
  ...
}
```

Why it exists:
- `state` defends the redirect (binds the callback to a specific session).
- `nonce` defends the ID token (binds the issued token to a specific auth request).

 With `nonce`, the client rejects any ID token whose `nonce` it didn't issue. It's the OIDC analogue of CSRF tokens, but for the token itself rather than the redirect.

 OAuth has nothing equivalent because OAuth never had a token for the client to consume directly — only access tokens for resource servers.

 ### /userinfo — the standardized "who is this user" endpoint
A single endpoint at the OP that returns user attributes as JSON, called with the access token:
```http
{
  "sub": "248289761001",
  "name": "Jane Doe",
  "given_name": "Jane",
  "family_name": "Doe",
  "email": "jane@example.com",
  "email_verified": true,
  "picture": "https://...",
  "locale": "en-US"
}
```
 Why it exists:
- The ID token carries identity assertion + a few key claims, but you don't want to bloat it with everything (it's a JWT in URL fragments, headers, logs…).
- The userinfo endpoint is for richer/larger profile data, fetched on demand.
- Pre-OIDC, Google/Facebook/Twitter each had their own ad-hoc "/me" endpoint with different shapes. OIDC standardized one.
The response can be plain JSON or a signed/encrypted JWT (for high-assurance use cases like FAPI).

The `sub` returned MUST match the `sub` in the `ID token `— that's how the client confirms userinfo isn't from a different user.

`jkt` = JWK Thumbprint — RFC 7638's SHA-256 hash of the canonical JSON form of a public JWK, base64url-encoded. Same value that ends up in the access token's `cnf.jkt` claim.

`dpop_jkt` = base64url( SHA-256( canonical_json(public_jwk) ) )
Example value: `0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I`
It appears on the authorization request:
```http
GET /authorize?
    response_type=code
    &client_id=app
    &scope=openid
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK...
    &code_challenge_method=S256
    &dpop_jkt=0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I    ← here
    &state=xyz
    &nonce=n-0S6
```
### What problem it solves
DPoP without `dpop_jkt` already binds access tokens to a key. But there's a window of vulnerability around the authorization code itself:
- Client A initiates an auth flow.
- An attacker steals the authorization code somehow (logs, referer leak, malicious browser extension, broken redirect URI handling).
- The attacker tries to redeem the code at` /token`.

PKCE blocks this because the attacker doesn't have the `code_verifier`. But consider a slightly different threat: a malicious honest-looking client / proxy that does see the code and the PKCE verifier — for instance, a compromised mobile SDK embedded in a legitimate app — and substitutes its own DPoP key at the token endpoint. The attacker now gets a DPoP-bound access token bound to their key, perfectly usable.

`dpop_jkt `closes this. The legitimate client commits its DPoP public-key thumbprint to the AS at the authorization step. The AS records it next to the issued code. When the token request arrives:
- The token-request DPoP proof's key thumbprint must match the `dpop_jkt` from the auth request.
- The issued access token is bound to that key.

The attacker can no longer swap the binding key, even if they captured the code and verifier.

### End-to-end flow
```sh
┌─────────┐                                          ┌──────┐                  ┌────┐
│ Client  │                                          │  AS  │                  │ RS │
└────┬────┘                                          └──┬───┘                  └─┬──┘
     │ 1. /authorize?dpop_jkt=<thumbprint>&...          │                        │
     │────────────────────────────────────────────────▶ │                        │
     │                                                  │ records jkt against    │
     │                                                  │ the issued code        │
     │ 2. redirect with code                            │                        │
     │◀──────────────────────────────────────────────── │                        │
     │                                                  │                        │
     │ 3. POST /token   (DPoP: <proof signed by key>)   │                        │
     │────────────────────────────────────────────────▶ │                        │
     │                                                  │ verify proof key       │
     │                                                  │ thumbprint == jkt      │
     │                                                  │ from step 1            │
     │ 4. access_token (cnf.jkt = <thumbprint>)         │                        │
     │◀──────────────────────────────────────────────── │                        │
     │                                                  │                        │
     │ 5. GET /api  Authorization: DPoP <token>                                  │
     │     DPoP: <proof for this request>                                        │
     │──────────────────────────────────────────────────────────────────────────▶│
     │                                                                           │
     │                                                  RS verifies proof key     │
     │                                                  matches token's cnf.jkt  │
```
`PKCE binds the code to the initiating client's secret material in flight; dpop_jkt binds the code to the key the resulting token will be bound to.`


## Symmetric Crypto > Pseudo Random Function (PRF)

### Hashing Algorithm
Formula that transform input into deterministic, fixed-length representational strings
Key characteristics: 
- Keyless — anyone can compute it. No secret involved.
- Deterministic — same input always yields same digest.
- Fixed output length — SHA-256 → 32 bytes; SHA-512 → 64 bytes; regardless of input size.
- Avalanche effect — flipping one input bit changes ~half the output bits.
`Do NOT use a raw hash for password storage. Hashes are fast — an attacker can try billions per second on a GPU. That's where KDFs come in.`
### Pseudo Random Function (PRF)
Transforms a Secret & Label into deterministic, arbitrary-length value indistinguishable from random data
Where PRFs show up:
- MAC / message authentication (HMAC).
- TLS key schedule — TLS 1.2's "PRF" expands the master secret into per-direction keys; TLS 1.3 uses HKDF (an HMAC-based PRF) for the same job with a cleaner extract-then-expand structure.
- Building block inside KDFs and AEAD modes.

#### Key Derivation Function (KDF)
PRF but more secure & more computationally expensive
`A function that takes input keying material (which may be non-uniform, e.g. a Diffie-Hellman shared secret or a user password) and produces one or more cryptographically strong keys.`
there are really two flavors of KDF and they exist for different threats.
##### Flavor A: KDFs for high-entropy input (HKDF, TLS 1.3 key schedule)
When the input is already strong but not uniform (e.g., a 256-bit ECDH shared secret), the KDF's job is to smooth it out and derive multiple independent keys from it.

`HKDF (RFC 5869) `has the canonical two-stage design:
```sh
PRK = HKDF-Extract(salt, IKM)        # condense raw input → uniform pseudorandom key
OKM = HKDF-Expand(PRK, info, L)      # stretch PRK into L bytes of output keying material
```
- `Extract` uses HMAC over the input keying material with a salt — this is the "randomness extractor."
- `Expand` is the chained-PRF construction shown above, with `info` providing domain separation (so the same PRK can derive a "client key", "server key", "IV", etc., that are independent).

HKDF is fast — there's no deliberate slowdown.

##### Flavor B: KDFs for low-entropy input (password hashing)
When the input is a human password — only ~30–50 bits of entropy — the KDF must be deliberately slow and memory-hard so an attacker who steals the database can't brute-force the password space cheaply.
Algorithms, in order of preference today:
- `Argon2id` — winner of the 2015 Password Hashing Competition; memory-hard; current best practice.
- `scrypt` — older memory-hard function; still acceptable.
- `bcrypt` — CPU-hard but not memory-hard; still widely used and acceptable for moderate threats.
- `PBKDF2` — only CPU iteration, no memory hardness; OK for FIPS-bound contexts but weak vs. GPU attackers.

The check at the API is an AND of two independent things:
- `Delegation check (scope)` — "Did the user authorize this client to perform this kind of action on their behalf?" Comes from the token's scope claim. E.g. `documents:read `means the client may attempt read operations.
- `Authorization check (subject's own rights)` — "Does the user (sub claim) actually have permission to touch this specific resource?" Comes from the RS's own ACL/RBAC/ABAC, not from the token.

A few corollaries that make this click:
- `Scopes are a ceiling, not a grant`. They cap what the client can do; they never grant the user new rights. If Alice can't read doc 42 normally, no scope can change that.
- `sub` is the principal. Authorization decisions on resources are about the user, not the client. The client just acts on their behalf.
- `client_id` may also factor in for client-only flows (client credentials), where there's no user — then scope + client identity is the authorization.

### Why it exists (`SecretKeyDerivation`)
OIDC lets the AS and a confidential client encrypt things to each other using the shared `client_secret` instead of public-key crypto. Examples:
- AS encrypting an ID token or UserInfo response to the client.
- Client encrypting a Request Object (request / request_uri payload) to the AS.
- JWE needs a real cryptographic key of a specific length (128/192/256 bits, sometimes 384/512). A `client_secret` is just a string — you can't feed it directly into AES. So the spec defines a deterministic derivation: hash the secret with SHA-256/384/512 and take the leftmost N bits.