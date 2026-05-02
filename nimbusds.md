## Hardware Security Module (HSM) / Cloud KMS Integration (Zero-Trust Key Management)
In strict environments, private keys never enter application memory. Instead, cryptographic operations are offloaded to an HSM, AWS KMS, or Azure Key Vault via a JCA (Java Cryptography Architecture) Provider.

Nimbus allows you to inject custom JCA providers into the signer/decrypter

## DPoP (Demonstrating Proof-of-Possession) for Token Bound Requests
OAuth 2.0 DPoP (RFC 9449) prevents token theft by binding an access token to a specific client-held public key. The client must prove possession of the private key on every API request

### How DPoP Actually Works
```sh
Step 1: Client initiates OAuth flow
  Client sends: authorization request
  (includes their public key OR generates one)

Step 2: Server issues access_token
  Server computes: thumbprint = SHA256(client's public key)
  Server creates token with CNF claim:
  
  {
    "sub": "customer-123",
    "aud": "api.bank.com",
    "scope": "pay",
    "cnf": {
      "jkt": "sha256-ABC123..."  ← Client's key thumbprint!
    },
    "exp": 1624234567
  }
  
  Server signs and sends this token

Important: The token REMEMBERS which public key it's bound to!

```
#### Client Creates DPoP Proof (Signing)
```sh
Client has:
  Private key: 0x7a4b9c2d... (SECRET)
  Public key:  0xaabbccdd... (PUBLIC)

Client creates JWT:
  Header: {alg: "ES256", jwk: <client's public key>}
  Claims: {htm: "POST", htu: "https://api.bank.com/pay", ...}

Client SIGNS (uses private key):
  DPoP = Sign(Header || Claims, private_key)
       = 0x5a6b7c8d... (cryptographic signature)

This signature PROVES: Only holder of private_key could create it
```
#### Client Sends Token + DPoP to API
```sh
HTTP Request:
  POST /api/payments
  Authorization: DPoP <access_token>
  DPoP: <JWT signature>  ← Proof of possession
  
API Server receives:
  - access_token (the credential)
  - DPoP (proof the client has the private key)
```

DPoP header is a JWS signed with the client's private key. The server can verify it using the public key in the header, and check that the thumbprint matches the cnf claim in the token.

jwk(JSON Web Key) is included in the DPoP header so the server can verify the signature without needing a separate key lookup. it contains the public key formatted as a json object with fields like `kty`, `crv`, `x`, and `y` for EC keys.

#### Server Verifies DPoP (Verification)
```sh
Server has:
  access_token: valid, not expired
  DPoP header: contains client's public key
  DPoP signature: cryptographic signature

Server VERIFIES (uses public key from DPoP header):
  Verify(DPoP signature, client's public key) → TRUE/FALSE

If TRUE:  "This request is from someone with the private key"
If FALSE: "This request is FORGED or signature wrong"
```

```sh
Priority 1: CNF Comparison (Fast Fail)
    ├─ Extract token's cnf.jkt
    ├─ Extract DPoP's public key
    ├─ Compute DPoP's thumbprint
    └─ Compare: token.cnf == dpop.thumbprint?
       If NO → REJECT immediately (don't waste CPU on signature)
       If YES → Continue

Priority 2: Signature Verification (Expensive)
    ├─ Verify DPoP signature
    ├─ Verify token signature (usually already done)
    └─ Verify htm/htu match request

Priority 3: Expiration & Other Claims
    ├─ Check DPoP not expired
    ├─ Check token not expired
    └─ Check scopes
```    
## Nested JWTs (Signed-then-Encrypted)
For PSD2 / Open Banking, you often need Non-Repudiation (Sender A signed it) AND Confidentiality (Only Receiver B can read it).

This requires creating a JWS, and setting it as the payload of a JWE

## Advanced Multi-Tenant JWT Processor
In a multi-tenant B2B fintech platform, you must dynamically look up the right JWKS end-point depending on the issuer before signature validation.Nimbus handles this via a `JWTClaimsSetAwareJWSKeySelector`

## JWT Revocation via JTI Blocklist (Distributed)
Nimbus has no built-in revocation — you must enforce it via the JTI claim against a fast distributed store (Redis, DynamoDB)

## ECDH-ES Key Agreement (Perfect Forward Secrecy)
Each encryption uses a freshly generated ephemeral EC key pair. If the recipient's long-term private key is later compromised, past messages remain safe

## Private Key JWT Client Authentication (RFC 7523)
Instead of sending a `client_secret`, the OAuth client signs a JWT assertion proving its identity to the token endpoint. Required by FAPI 2.0

## mTLS Certificate-Bound Access Tokens (RFC 8705)
The API gateway computes the SHA-256 thumbprint of the client's TLS certificate and checks it matches the cnf.x5t#S256 claim in the access token — preventing token theft even over stolen tokens.

## SD-JWT (Selective Disclosure, Draft RFC)
Emerging standard for privacy-preserving credentials (e.g., KYC verification where you prove age without revealing full DOB). Nimbus 10.x has early support.

## JAR — JWT-Secured Authorization Requests (RFC 9101)
Mandatory in FAPI 1.0 Advanced. The entire OAuth /authorize redirect is packed into a signed JWT request parameter, preventing parameter tampering.

## JARM — JWT Authorization Response Mode
FAPI 2.0 mandates the authorization server returns the `code` and `state` back inside a signed JWT rather than raw query parameters — preventing authorization code interception.

## Rich Authorization Requests (RAR — RFC 9396)
For PSD2 payment initiation: instead of a simple `scope=payments`, the JWT encodes the exact payment details (amount, creditor IBAN, currency) the user is authorising. Prevents scope escalation.

## Token Exchange (RFC 8693) — On-Behalf-Of for Microservices
A payment service receives a user access token and exchanges it for a scoped downstream token (e.g., to call a fraud-check service). Required in microservice architectures that follow the user context through the call chain.

## ID Token Binding Claims (at_hash, c_hash, nonce)
Mandatory OIDC validation step. The `at_hash` ties the ID token to the exact access token issued — if they don't match, it signals a token substitution attack.

## SCA Claims Validation — PSD2 Strong Customer Authentication (acr, amr)
PSD2 mandates SCA (two-factor) for payment initiation. The auth server encodes the authentication methods in `amr` and the assurance level in `acr`. The payment API must reject tokens that don't prove SCA was performed.

## VC-JWT — W3C Verifiable Credentials (KYC / AML Digital Identity)
Regulated fintech KYC: instead of re-uploading passport photos for every provider, the user holds a VC-JWT credential issued by an identity verifier (e.g., Yoti, Jumio). The fintech verifies the credential cryptographically.

## HS256 Symmetric Tokens for Internal Microservices
High-throughput internal APIs (fraud scoring, ledger, risk engine) where asymmetric crypto overhead is unnecessary and the secret is managed by a secrets manager.

## Software Statement Assertion (SSA) — Open Banking TPP Onboarding
The most critical Open Banking flow: a TPP receives a signed SSA from the Trust Framework directory (e.g., FCA, Open Banking Ltd). It presents this SSA during Dynamic Client Registration at each bank. Without it, no TPP can legally operate.

## Step-Up Authentication Challenge (RFC 9470)
The payment API detects a high-risk transaction mid-flow and demands re-authentication at a higher ACR — without terminating the session. The resource server embeds the required `acr_values` in a `WWW-Authenticate `challenge header

## A256GCMKW Symmetric Key Wrapping for Internal Encrypted Tokens
Symmetric `AES-GCM` key wrapping is the fastest JWE option for high-throughput internal service communication (e.g., wrapping an ephemeral CEK per request).

## JWE DEFLATE Compression for Large Claim Sets
When tokens carry consent permissions, RAR details, or ISO 20022 payment data, the payload can exceed 4KB and break HTTP header limits. DEFLATE compression typically reduces by 60–70%.

## Consent JWT — Encoding Open Banking Permissions in the Token
Instead of looking up consent state in a database on every API call, the access token carries the full consent payload (permitted accounts, scopes, expiry) as a JWT claim. The API validates it inline — zero database round-trips.

## PBES2 Key Encryption — Key Ceremony / Backup / Export
PBES2 (Password-Based Encryption Scheme 2) is a standard from PKCS#5 (RFC 8018) for encrypting data using a key derived from a password.
When a private key must be exported (e.g., key escrow for regulatory access, HSM backup), it is encrypted with a password-derived key using PBES2. No additional shared key infrastructure needed.

## Custom Critical Header Parameters (crit) Enforcement
Open Banking and FAPI profiles define proprietary critical headers (e.g., `ob-signing-date`, `ob-signing-algo-id`). Any JWT processor that doesn't understand a `crit` header must reject the token. Nimbus enforces this, but you must register your custom params.

## JWT-Based Tamper-Evident Audit Log
Each audit entry is signed with the hash of the previous entry (chained log). Any tampering breaks the chain. Satisfies PCI-DSS 10.3 and SOX audit trail requirements.

## OIDC Aggregated & Distributed Claims (KYC from External Providers)
A bank's ID token can reference claims held by a third-party KYC provider (AML screening result, credit score, identity verification level) without copying the PII into its own tokens. The claims are fetched on demand by the relying party.

## ECDH-1PU — Authenticated Sender Encryption (ECDH1PUEncrypter)
Standard ECDH-ES only provides confidentiality. ECDH-1PU (draft-madden-jose-ecdh-1pu) folds the sender's static private key into the KDF, so the recipient can cryptographically verify the message came from a specific sender — without a separate JWS signature. Used in encrypted DMs between financial institutions

## X25519 Key Encryption (X25519Encrypter)
ECDH-ES over Curve25519 instead of P-256. Faster, no cofactor attacks, no risk of weak parameters. Preferred for modern OKP (`OctetKeyPair`) key material from identity wallets and mobile SDKs.

## XChaCha20-Poly1305 Content Encryption (XC20P)
Alternative to AES-GCM for content encryption. Nonce-misuse resistant — catastrophically weaker nonce reuse in AES-GCM is a known production failure mode. XC20P uses a 192-bit nonce vs AES-GCM's 96-bit. Required in some FIDO2 / passkey ecosystems.

## Direct Key Encryption (DirectEncrypter / dir)
When a shared symmetric secret is the content encryption key — no key wrapping overhead. Used for ultra-low-latency internal channels (e.g., real-time fraud scoring pipeline) where the CEK is pre-shared via Vault and rotated out-of-band.

## JWE Multiple Recipients (MultiEncrypter / JWEObjectJSON)
Encrypt one payload once for multiple recipients — each gets their own encrypted CEK in the JWE JSON recipients array. Used in consortium payments where a transaction record must be readable by the initiating bank, clearing house, and regulator simultaneously.

## Production JWKS Source Resilience (JWKSourceBuilder)
The library has `OutageTolerantJWKSetSource`, `RetryingJWKSetSource`, `RateLimitedJWKSetSource`, and `RefreshAheadCachingJWKSetSource`. Not using these in production means a JWKS endpoint blip kills your token validation. This is the most critical production operations concern

## JWE `enc` Algorithms

| `enc` value      | Algorithm              | Key size       | Notes                        |
|------------------|------------------------|----------------|------------------------------|
| `A128GCM`        | AES-GCM                | 128-bit        | Fast, authenticated          |
| `A256GCM`        | AES-GCM                | 256-bit        | Most common in fintech       |
| `A128CBC-HS256`  | AES-CBC + HMAC-SHA256  | 256-bit (split)| Encrypt-then-MAC             |
| `A256CBC-HS512`  | AES-CBC + HMAC-SHA512  | 512-bit (split)| Stronger MAC                 |
| `XC20P`          | XChaCha20-Poly1305     | 256-bit        | Nonce-misuse resistant       |

## alg=none Attack Prevention (PlainJWT rejection)
A classic JWT attack: downgrade to `alg=none` so no signature is checked. Your processor must explicitly reject it. Many production systems omit this check.

## secp256k1 / ES256K — Blockchain & DeFi
`ES256K` (ECDSA over `secp256k1`) is the curve used by Bitcoin and Ethereum. Regulated DeFi custody services, CBDC wallets, and blockchain-anchored identity systems sign JWTs with this curve to interoperate with on-chain key material.

## PEM Key Loading (PEMEncodedKeyParser / X509CertUtils)
In production, keys arrive as PEM files from cert management systems (Vault PKI, cert-manager, AWS ACM). The library has `PEMEncodedKeyParser` and `X509CertUtils`

## AES Key Wrap without GCM (A256KW) — NIST Standard
The `A128KW` / `A256KW` variants (without GCM) are required by some NIST SP 800-56C and PCI PIN Security compliance profiles. Distinct from `A256GCMKW` — simpler, widely supported, but lacks authenticated key wrapping

## JWE Architecture: The Two-Layer Model
Every JWE has two separate encryption operations:

```sh
┌─────────────────────────────────────────────────────┐
│                     JWE                             │
│                                                     │
│  Layer 1: Key Management  →  encrypts the CEK       │
│  Layer 2: Content Encryption → encrypts the payload │
└─────────────────────────────────────────────────────┘
```
The `alg` header controls Layer 1. The `enc` header controls Layer 2. They are always independent.

### Layer 2 First: Content Encryption (enc)
The actual payload is always encrypted with a fresh random symmetric key called the `Content Encryption Key` (CEK). This never changes regardless of `alg`.

| `enc` value      | Algorithm              | Key size       | Notes                        |
|------------------|------------------------|----------------|------------------------------|
| `A128GCM`        | AES-GCM                | 128-bit        | Fast, authenticated          |
| `A256GCM`        | AES-GCM                | 256-bit        | Most common in fintech       |
| `A128CBC-HS256`  | AES-CBC + HMAC-SHA256  | 256-bit (split)| Encrypt-then-MAC             |
| `A256CBC-HS512`  | AES-CBC + HMAC-SHA512  | 512-bit (split)| Stronger MAC                 |
| `XC20P`          | XChaCha20-Poly1305     | 256-bit        | Nonce-misuse resistant       |

`AES-GCM` provides `Authenticated Encryption with Associated Data `(AEAD) — confidentiality + integrity in one operation. The JWE header bytes are fed in as AAD (Additional Authenticated Data), meaning the header is integrity-protected even though it is not encrypted

```sh
Payload ──────────────────────────────────────────────┐
                                                       ▼
CEK (random, fresh per message) ──► AES-GCM(enc=A256GCM) ──► Ciphertext + Auth Tag
                                                       ▲
JWE Header bytes ─────────────────────────────────────┘ (AAD — not encrypted but authenticated)
```

You have a message `M`. You want both:
- `Confidentiality`: only the recipient can read it.
- `Authenticity`: the recipient knows who wrote `M`.

For JWE, there are two layers of encryption:
- `data encryption` (Layer 2) — encrypts the actual message M with a random CEK using AES-GCM or AES-CBC+HMAC. The `enc` header picks how this works.

- `key management` (Layer 1) — encrypts the CEK itself so the recipient can recover it. The `alg` header picks how this works.

Encryption was never claimed to bind the author to the contents — only the signature does

If you sign ciphertext, you've proved who handled the ciphertext — which is almost never what you actually wanted. If you sign plaintext, you've proved who wrote the plaintext 

`A signature only proves authorship of the bytes it was computed over.`

By construction the session key is known to exactly two endpoints..

### Layer 1: Key Management (alg) — How the CEK is Delivered
The `CEK` itself must be delivered to the recipient. The `alg` field determines how. There are five distinct mechanisms:

#### Mechanism 1 — Key Wrapping (AES-KW)
The `CEK` is encrypted with a symmetric wrapping key using `AES Key Wrap` (RFC 3394). Simple, fast, no public key crypto.

```sh
alg: A128KW / A192KW / A256KW
     A128GCMKW / A192GCMKW / A256GCMKW   ← GCM variant (authenticated wrap)
```
```sh
CEK ──────────────────────────────────────────────────────────────────────┐
                                                                           ▼
Shared Wrapping Key (pre-distributed) ──► AES-KW or AES-GCM-KW ──► Encrypted CEK
```

AES-KW vs AES-GCMKW:
- `A256KW` — RFC 3394 Key Wrap. No authentication of the key wrap itself. Required by NIST SP 800-56C, PCI PIN.
- `A256GCMKW` — AES-GCM Key Wrap. The wrap includes an IV and Auth Tag per key-wrap operation — stronger, prevents key wrap forgery. Has two extra header fields: iv and tag.
- When to use: Internal microservices sharing a symmetric key via Vault. Fast — no RSA/EC math.

#### Mechanism 2 — Asymmetric Key Encryption (RSA)
The CEK is encrypted directly with the recipient's RSA public key.

```sh
alg: RSA-OAEP-256 / RSA-OAEP-384 / RSA-OAEP-512   ← use these
     RSA-OAEP                                        ← legacy (SHA-1 based)
     RSA1_5                                          ← NEVER use (padding oracle attacks)
```
```sh
CEK ──────────────────────────────────────────────────────────────────────┐
                                                                           ▼
Recipient RSA Public Key ──► RSA-OAEP-256 ──────────────────► Encrypted CEK
```
When to use: Encrypting payloads for external partners where you only have their public key. Sender does not need to prove identity.

#### Mechanism 3 — Key Agreement (ECDH-ES)
No CEK is transmitted at all. Both parties independently derive the same shared secret using Diffie-Hellman. The shared secret either IS the CEK (`ECDH-ES`) or wraps the CEK (ECDH-ES+A256KW).

```sh
alg: ECDH-ES           ← shared secret IS the CEK (direct derivation)
     ECDH-ES+A128KW    ← shared secret wraps the CEK
     ECDH-ES+A256KW    ← shared secret wraps the CEK (256-bit)
```
```sh
Sender ephemeral private key  ─┐
                                ├──► ECDH + Concat KDF ──► Shared Secret ──► CEK
Recipient static public key   ─┘                                    (or wraps CEK)

Recipient ephemeral public key is embedded in the JWE header ('epk' field)
Recipient uses their static private key + the 'epk' to derive the same secret
```
Perfect Forward Secrecy: A fresh ephemeral key is generated for every encryption. If the recipient's long-term private key is compromised later, past messages cannot be decrypted.

Also works over X25519 (OKP keys) — same mechanism, Curve25519 math instead of P-256.

#### Authenticated Key Agreement (ECDH-1PU)
Extension of ECDH-ES that folds the sender's static private key into the KDF. The recipient can verify the sender's identity from the key derivation alone — no outer JWS signature needed.

```sh
alg: ECDH-1PU          ← sender-authenticated, shared secret IS CEK
     ECDH-1PU+A256KW   ← sender-authenticated, shared secret wraps CEK
```
```sh
Sender static private key    ─┐
Sender ephemeral private key ─┼──► ECDH-1PU KDF ──► Shared Secret ──► CEK
Recipient static public key  ─┘

Only someone holding the sender's static private key could have produced this message.
```
When to use: Encrypted messaging between two identified institutions where you need both confidentiality AND sender authentication, without the overhead of a nested JWS+JWE

#### Direct Key (dir)
No key management at all. The shared symmetric key is the CEK. Nothing is transmitted in the encrypted key field.

```sh
alg: dir
```
```sh
Pre-shared Key (from Vault, KMS) ══════════════════════════════════════► CEK
                                                    (the key IS the CEK — no wrapping)
```
When to use: Ultra-low-latency internal channels where CEK rotation is managed externally (Vault dynamic secrets, AWS Secrets Manager). Zero overhead — fastest possible JWE. Key must be exactly the right bit length for the enc algorithm.

#### Password-Based (PBES2)
The CEK is wrapped with a key derived from a human-memorable passphrase via PBKDF2.

```sh
alg: PBES2-HS256+A128KW
     PBES2-HS384+A192KW
     PBES2-HS512+A256KW
```
```sh
Passphrase ──► PBKDF2(salt, iterations) ──► Derived Key ──► AES-KW ──► Encrypted CEK
```
When to use: Key escrow exports, disaster recovery backups, regulatory handover of key material. Not for API traffic — PBKDF2 is intentionally slow.

### JWE Wire Format
```sh
BASE64URL(header) . BASE64URL(encryptedKey) . BASE64URL(iv) . BASE64URL(ciphertext) . BASE64URL(tag)
        │                    │                      │                  │                    │
   alg + enc           CEK encrypted          AES-GCM IV         Encrypted          Auth tag over
   + keyID             by alg mechanism       (96 bits)           payload         ciphertext + AAD
```   

Lists the exact operations the key is permitted to perform.

| Value        | Constant                   | Layer                                    |
|--------------|----------------------------|------------------------------------------|
| `sign`       | `KeyOperation.SIGN`        | JWS — produce signature                  |
| `verify`     | `KeyOperation.VERIFY`      | JWS — verify signature                   |
| `encrypt`    | `KeyOperation.ENCRYPT`     | JWE — encrypt CEK (key management layer) |
| `decrypt`    | `KeyOperation.DECRYPT`     | JWE — decrypt CEK                        |
| `wrapKey`    | `KeyOperation.WRAP_KEY`    | JWE — wrap CEK with AES-KW / RSA         |
| `unwrapKey`  | `KeyOperation.UNWRAP_KEY`  | JWE — unwrap CEK                         |
| `deriveKey`  | `KeyOperation.DERIVE_KEY`  | ECDH-ES — derive CEK from shared secret  |
| `deriveBits` | `KeyOperation.DERIVE_BITS` | Raw bit derivation                       |

```java
// HSM-constrained key — can only sign, never verify or export
ECKey hsmKey = new ECKeyGenerator(Curve.P_256)
    .keyOperations(Set.of(KeyOperation.SIGN))
    .generate();

// Key-wrapping-only key — AES key that wraps/unwraps other keys, nothing else
OctetSequenceKey wrappingKey = new OctetSequenceKeyGenerator(256)
    .keyOperations(Set.of(KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY))
    .generate();
```

The Distinction: wrapKey vs encrypt

They look the same but refer to different layers of JWE:
```sh
encrypt / decrypt  ──► Content Encryption Layer  ──► encrypts the PAYLOAD with the CEK
wrapKey / unwrapKey ──► Key Management Layer      ──► encrypts the CEK itself
```
In practice for JWE:
- The CEK encrypts the payload → `encrypt` / `decrypt`
- The wrapping key encrypts the CEK → `wrapKey` / `unwrapKey`

```java
// A key used only to wrap CEKs — it never touches payload data
OctetSequenceKey cekWrappingKey = new OctetSequenceKeyGenerator(256)
    .algorithm(JWEAlgorithm.A256GCMKW)
    .keyOperations(Set.of(KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY))
    .generate();

// A key used for content encryption (rare — usually CEK is ephemeral)
OctetSequenceKey contentKey = new OctetSequenceKeyGenerator(256)
    .keyOperations(Set.of(KeyOperation.ENCRYPT, KeyOperation.DECRYPT))
    .generate();
```
They MUST NOT conflict if both are present.

| `use` | Permitted `key_ops`                                               |
|-------|-------------------------------------------------------------------|
| `sig` | `sign`, `verify`                                                  |
| `enc` | `encrypt`, `decrypt`, `wrapKey`, `unwrapKey`, `deriveKey`, `deriveBits` |

```java
// VALID — use=sig with sign+verify ops
ECKey valid = new ECKeyGenerator(Curve.P_256)
    .keyUse(KeyUse.SIGNATURE)
    .keyOperations(Set.of(KeyOperation.SIGN, KeyOperation.VERIFY))
    .generate();

// INVALID — use=sig but key_ops contains wrapKey — library will throw
ECKey invalid = new ECKeyGenerator(Curve.P_256)
    .keyUse(KeyUse.SIGNATURE)
    .keyOperations(Set.of(KeyOperation.SIGN, KeyOperation.WRAP_KEY)) // conflict!
    .generate();
```
Where JWS proves who wrote it, JWE guarantees only the recipient can read it — and, because all JWE algorithms are AEAD, also that the ciphertext wasn't tampered with.

Almost every JWE uses hybrid encryption:
1. Generate a fresh random symmetric key — the Content Encryption Key (CEK).
2. Encrypt the payload with the CEK using a fast symmetric AEAD cipher (AES‑GCM or AES‑CBC+HMAC).
3. Encrypt (or derive, or just transmit) the CEK so the recipient can recover it. How you do step 3 is what the `alg` header picks. Step 2 is what `enc` picks.

So a JWE header always has two algorithm parameters:

| Header | Role | Examples |
|---|---|---|
| `alg` | Key management — how the CEK gets to the recipient | `RSA-OAEP-256`, `ECDH-ES+A256KW`, `A256KW`, `dir`, `PBES2-HS512+A256KW` |
| `enc` | Content encryption — how the payload is encrypted with the CEK | `A128GCM`, `A256GCM`, `A128CBC-HS256`, `A256CBC-HS512` |

A JWE compact-serialized token looks like:
`BASE64URL(header) . BASE64URL(encrypted_key) . BASE64URL(iv) . BASE64URL(ciphertext) . BASE64URL(auth_tag)`
Five base64url segments separated by dots (JWS has three). Compare:

JWS: `header.payload.signature`
JWE: `header.encrypted_key.iv.ciphertext.tag`
Each part:  
- `Protected header` — JSON, base64url-encoded. Authenticated as Additional Authenticated Data (AAD) by the AEAD cipher. Not secret.
- `Encrypted key` — the wrapped/encrypted CEK. Empty for dir and (mostly) for ECDH-ES.
- `IV` — initialization vector / nonce for the content cipher.
- `Ciphertext` — encrypted payload.
- `Auth tag `— AEAD authentication tag over (`AAD || IV || ciphertext`)
### How JWKMatcher Uses These Fields
When the processor fetches keys from a JWKS, `JWKMatcher` filters by these fields:
```java
// Only match keys that: are EC, have use=sig, have this specific kid
JWKMatcher matcher = new JWKMatcher.Builder()
    .keyType(KeyType.EC)
    .keyUse(KeyUse.SIGNATURE)
    .keyID("sig-2026-04")
    .algorithm(JWSAlgorithm.ES256)
    .build();

List<JWK> candidates = new JWKSelector(matcher).select(jwkSet);
``` 
This is what happens automatically inside `JWSVerificationKeySelector` — it builds the matcher from the JWT header and filters your JWKS

`wrapping/unwrapping is exclusively a JWE concept`

### Why the Distinction Exists
wrapKey and encrypt are different operations on different data:
```sh
wrapKey  ──► operates on a KEY   (the CEK, which is ~16–32 bytes of key material)
encrypt  ──► operates on DATA    (the actual payload — could be megabytes)
```
The RFC deliberately separated them so an HSM or KMS can be configured with a key that only wraps other keys and cannot be used to encrypt arbitrary data — a common security boundary in PCI-DSS environments.

```java
// This key can ONLY wrap/unwrap CEKs — cannot encrypt payload data directly
OctetSequenceKey cekWrappingKey = new OctetSequenceKeyGenerator(256)
    .keyOperations(Set.of(KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY))
    .generate();

// This key can ONLY encrypt/decrypt payload data — cannot wrap keys
OctetSequenceKey contentKey = new OctetSequenceKeyGenerator(256)
    .keyOperations(Set.of(KeyOperation.ENCRYPT, KeyOperation.DECRYPT))
    .generate();
```
| `key_ops`    | JWS or JWE | What it operates on                               |
|--------------|------------|---------------------------------------------------|
| `sign`       | JWS only   | Payload bytes → produces signature                |
| `verify`     | JWS only   | Signature bytes → true/false                      |
| `wrapKey`    | JWE only   | CEK (key bytes) → encrypted key                   |
| `unwrapKey`  | JWE only   | Encrypted key → CEK (key bytes)                   |
| `encrypt`    | JWE only   | Payload data → ciphertext                         |
| `decrypt`    | JWE only   | Ciphertext → payload data                         |
| `deriveKey`  | JWE only   | ECDH-ES — derives CEK from shared secret          |
| `deriveBits` | JWE only   | Raw bit derivation (lower-level than `deriveKey`) |

### One Edge Case: alg=dir
With dir (direct key), there is no wrapping — the shared key is the CEK. So for dir, the correct `key_ops` is `encrypt`/`decrypt`, not `wrapKey`/`unwrapKey`:
```java
// dir key — no wrapping, the key IS the CEK
OctetSequenceKey directKey = new OctetSequenceKeyGenerator(256)
    .algorithm(JWEAlgorithm.DIR)
    .keyOperations(Set.of(KeyOperation.ENCRYPT, KeyOperation.DECRYPT)) // not wrapKey
    .generate();
```

### AES-KW / AES-GCMKW — Pre-Shared Out-of-Band
The wrapping key is never transmitted. It must be agreed upon before any JWE is sent, through a separate secure channel.

```sh
How it gets shared in production:
─────────────────────────────────
  Service A and Service B both read the same secret from Vault/KMS at startup.
  The secret never appears in any JWE token — ever.

  Vault ──► Service A reads key ──┐
  Vault ──► Service B reads key ──┘  (same key, both sides know it)

  Service A encrypts CEK with wrapping key ──► JWE token ──► Service B
  Service B decrypts CEK with same wrapping key
  ```

  The problem: How did both services get the same key securely in the first place? That is solved by Vault/KMS — which is a chicken-and-egg problem solved by identity-based authentication (IAM roles, mTLS, etc.) at the infrastructure level.

  ### RSA-OAEP — Public Key Infrastructure
No pre-sharing needed. The recipient publishes their public key (anyone can see it). The sender uses it to wrap the CEK. Only the recipient's private key can unwrap.

```sh
Recipient generates key pair once:
──────────────────────────────────
  Private key ──► stays secret, never leaves recipient
  Public key  ──► published in JWKS at /.well-known/jwks.json  (anyone can fetch)

At encryption time:
───────────────────
  Sender fetches recipient's public key from JWKS
  Sender wraps CEK with public key ──► Encrypted CEK travels in JWE
  Recipient unwraps CEK with private key

The wrapping key (public key) is PUBLIC — no secure channel needed to share it.
```
```java
// Sender: fetch recipient's public key (no secret channel needed)
RSAKey recipientPublicKey = fetchFromJWKS("https://partner.bank.com/.well-known/jwks.json");
jwe.encrypt(new RSAEncrypter(recipientPublicKey));

// Recipient: use their private key (never shared with anyone)
RSAKey myPrivateKey = vault.getPrivateKey("my-enc-key");
jwe.decrypt(new RSADecrypter(myPrivateKey));
```
### ECDH-ES — The Wrapping Key Is Never Shared At All
This is the elegant one. No key is shared — the wrapping key is mathematically derived independently by both sides from a fresh ephemeral key pair.
```sh
Sender generates a fresh ephemeral EC key pair for THIS message only:
─────────────────────────────────────────────────────────────────────
  Sender ephemeral private key  ──┐
                                   ├──► ECDH math ──► Shared Secret ──► KDF ──► CEK
  Recipient static public key   ──┘

  Sender embeds ephemeral PUBLIC key in JWE header ('epk' field) — not secret

Recipient derives the same CEK independently:
─────────────────────────────────────────────
  Sender ephemeral public key (from 'epk' header) ──┐
                                                      ├──► ECDH math ──► same Shared Secret ──► same CEK
  Recipient static private key                      ──┘

Result: Both sides arrive at the same CEK without ever transmitting it.
```
```sh
JWE Header contains:
  "alg": "ECDH-ES+A256KW",
  "epk": { "kty":"EC", "crv":"P-256", "x":"...", "y":"..." }  ← sender's ephemeral PUBLIC key
          ↑ not secret — recipient needs this to do the ECDH math
```
The wrapping key is never shared — it emerges from the mathematics on both sides independently. This is Diffie-Hellman

### PBES2 — Shared via Human Agreement
The wrapping key is derived from a passphrase. The passphrase is shared through a human channel — phone call, secure message, in-person handover.
```sh
Key ceremony:
─────────────
  Custodian A tells Custodian B the passphrase over an encrypted phone call.
  Both feed it into PBKDF2 independently → same wrapping key derived on both sides.
  The passphrase itself never appears in any token.
```  

## Used in Production
### RSA-OAEP-256 — Most Common
The default choice for B2B encryption. Every bank, TPP, and payment processor has RSA infrastructure already. Simple — sender only needs the recipient's public key from their JWKS

```sh
Used by: Open Banking, PSD2 TPP-to-bank, partner API encryption, UserInfo endpoint
```
### ECDH-ES+A256KW — Growing Fast
Preferred for new systems. Smaller keys than RSA, Perfect Forward Secrecy built-in, required by modern identity wallet specs (DIF, W3C DID).

```sh
Used by: FAPI 2.0 new implementations, VC/DID ecosystems, mobile SDKs, CIBA flows
```
### A256GCMKW / A256KW — High-Throughput Internal
Internal microservice-to-microservice. Pre-shared via Vault. No asymmetric math — fastest possible key management.

```sh
Used by: Fraud scoring pipelines, ledger services, inter-service event queues
         Anywhere latency matters and both services are in the same trust domain
```

## Three Azure Key Vault Object Types
### Secrets — Stored as Plaintext
```sh
Your app stores:  "my-aes-key" → "base64encodedkeyvalue..."
Azure stores it:  encrypted at rest using Microsoft's managed keys (AES-256)
Your app reads:   the plaintext value back over TLS
```
```sh
  Your app's Managed Identity ──► Azure AAD ──► RBAC check ──► Vault API ──► plaintext value
                                                    ↑
                              THIS is the security control,
```                              
### Keys — Never Leave the Vault (HSM-backed)
```sh
Your app stores:  an RSA or AES key
Azure stores it:  in an HSM (Hardware Security Module) — FIPS 140-2 Level 2 or 3
Your app gets:    NOTHING — the key never leaves

Instead your app sends: "please sign/decrypt this data"
Azure performs the operation INSIDE the HSM and returns the result
```
The raw key bytes are never accessible. This is the fundamental difference from Secrets. Used for:
- RSA signing keys (JWS PS256)
- AES-GCM encryption (JWE A256GCM)
- Key wrapping operations

### Certificates — Managed X.509
```sh
Azure manages: key generation + CSR + renewal + private key (HSM-backed)
Your app gets: the certificate chain (public) — private key stays in HSM
```

## SAML Tracer firefox extension — inspect SAML and JWT tokens in the browser

## Multi-Level Signing — Cosigner Consensus (M-of-N)
A payment over $1M requires approval from 3 out of 5 risk officers. Each signs the same JWT sequentially. Only after all M signatures are collected is the payment authorized.

## Token Morphing — Convert JWS to JWE and Back
A signed token needs to cross untrusted networks. Temporarily encrypt the JWS, then unwrap it on the other side.

## Dynamic Algorithm Selection (Runtime Capability Detection)
Your org supports both RSA and EC keys. Algorithm selection depends on:
- Which keys are available
- Request source (mobile app vs web)
- Compliance requirements (FIPS mode?)

## Token Encryption at Rest (Database Storage)
Tokens stored in the database should be encrypted. On read, decrypt before validating.

## Token Attestation (Proof of Execution)
A payment token proves it was approved by a legitimate payment engine, not forged. Uses TPM/TEE attestation.

## Zero-Knowledge Proof Token (Privacy-Preserving Claims)
Prove a claim (e.g., "I am over 18") without revealing the actual date of birth.

## PBKDF2 (Password-Based Key Derivation Function)
### Employee Device PIN Protection
```sh
Scenario: Bank employee logs into mobile workstation with PIN├── PIN: "4837" (user input, low entropy)├── PBKDF2(password=PIN, salt=random, iterations=600000, hash=SHA-512)├── Output: 256-bit symmetric key└── Use: AES-256 encryption of HSM credentials on device
```
### Backup Code Recovery
```sh
Scenario: User loses 2FA device, needs backup codes to regain access
├── Master backup seed: "SEED-1234-5678-9012" (user writes down)
├── PBKDF2(seed, salt=user_id, iterations=500000, hash=SHA-256)
├── Output: Used to derive individual backup code encryption keys
└── Each backup code stored encrypted under different derived key
```

## HKDF (HMAC-Based Key Derivation Function)
### Ephemeral Session Key Derivation
```sh
Scenario: ECDH-ES key agreement in open banking (PSD2 payment)
├── Sender generates ephemeral EC keypair
├── DH agreement produces shared secret S (128 bits, not enough entropy directly)
├── HKDF-Expand(PRK=HMAC-SHA256(salt="", IKM=S), info="JWE Encryption", L=256)
├── Output: Full 256-bit CEK for AES-256-GCM
└── Use: Encrypt payment authorization details
```

### Multi-Purpose Key Derivation
```sh
Scenario: Single master key used for multiple purposes
├── Master key: 256-bit random (HSM-generated)
├── Purpose 1: HKDF(info="signing-key", output_length=256) → JWS signing key
├── Purpose 2: HKDF(info="encryption-key", output_length=256) → JWE CEK
├── Purpose 3: HKDF(info="hmac-key", output_length=512) → HMAC authentication
└── Each derived key cryptographically isolated by "info" parameter
```

## ECDH Key Derivation (Elliptic Curve Diffie-Hellman)
### Zero Pre-Shared Secrets with Partners
```sh
Scenario: Bank A encrypts payment to Bank B (no prior key exchange)
├── Bank A generates ephemeral EC keypair (one-time use)
├── Bank B publishes static EC public key in JWKS
├── ECDH math derives same shared secret on both sides
│   (A's ephemeral private + B's static public)
│   = (A's ephemeral public + B's static private)
├── Shared secret → HKDF → CEK
└── Bank A sends: encrypted payload + ephemeral public key (in JWE header)
└── Bank B receives, uses private key to derive same CEK, decrypts
```
### Perfect Forward Secrecy (PFS) in Payment Streams
```sh
Scenario: Continuous payment data encryption (e.g., transaction log)
├── Session 1: Generate ephemeral key pair 1 → derive CEK 1 → encrypt batch
├── Destroy ephemeral key 1
├── Session 2: Generate ephemeral key pair 2 → derive CEK 2 → encrypt batch
├── ...
└── If CEK 1 leaked: only that batch exposed, not future batches
```
FAPI 2.0 mandates ECDH-ES for PFS.

## Key Stretching (Time-Hard Functions)
### Account Lockout via Computational Delay
```sh
Scenario: Brute-force attack on password login
├── Attacker tries: password1, password2, ... (1000s/sec)
├── System runs PBKDF2(attempt, iterations=600000)
├── Each attempt takes ~100ms (computational cost)
├── 10 attempts = 1 second total; impossible to try 1 million passwords
└── Legitimate user (1 login/month) waits ~100ms once
```
### Argon2 for High-Value Operations
```sh
Scenario: Signing a $10M wire transfer (extreme authentication)
├── User enters PIN
├── System runs Argon2id(pin, memory=256MB, iterations=3, parallelism=4)
├── Computation takes ~2 seconds + 256MB RAM
├── GPU attack becomes impractical (need 256MB per thread)
└── Protects against adversary with warehouse of GPUs
```
Why Argon2 > PBKDF2: Argon2 also uses memory (not just CPU time).

## ECDH-1PU (Authenticated ECDH)
### Payment Authorization with Sender Authentication
```sh
Scenario: Customer initiates payment; bank must verify sender identity
├── Old way (ECDH-ES): Only proves bank received from *someone* with ephemeral key
│   Issue: Could be MITM
│
├── New way (ECDH-1PU+A256KW):
│   Customer static private key + ephemeral + bank static public key
│   = ECDH-1PU derives same secret ONLY if customer used their private key
│   = Mathematically proves sender identity
│
└── Encryption + authentication in single operation
```
## Key Wrapping (AES-KW, RSA-OAEP)
### Symmetric Key Wrapping for Key Distribution
```sh
Scenario: Bank distributes encryption keys to ATM network
├── Master HSM Key: AES-256
├── ATM 1 needs: own encryption key (different for each ATM)
├── Process:
│   1. Generate random ATM-1 key (256 bits)
│   2. AES-KW(master_key, atm_1_key) = wrapped_key_1
│   3. Send wrapped_key_1 to ATM-1
│   4. ATM-1 decrypts using master_key → recovers atm_1_key
│
└── Benefit: Master key never leaves HSM
    Each ATM gets individually wrapped key
```
```java
SecretKey masterKey = ...; // from HSM

// Generate ATM-specific key
SecureRandom random = new SecureRandom();
byte[] atmKeyBytes = new byte[32];
random.nextBytes(atmKeyBytes);

// Wrap it
JWEAlgorithm alg = JWEAlgorithm.A256KW;  // AES Key Wrap
EncryptionMethod enc = EncryptionMethod.A256GCM;

AESEncrypter wrappingEncrypter = new AESEncrypter(masterKey);
JWEObject wrappedJwe = new JWEObject(
    new JWEHeader(alg, enc),
    new Payload(atmKeyBytes)
);
wrappedJwe.encrypt(wrappingEncrypter);
// wrappedJwe.serialize() → send to ATM

// ATM-side decryption
AESDecrypter wrappingDecrypter = new AESDecrypter(masterKey);
wrappedJwe.decrypt(wrappingDecrypter);
byte[] recoveredKey = wrappedJwe.getPayload().toBytes();
```

### Asymmetric Key Wrapping for Partner Encryption
```sh
Scenario: Investment bank encrypts trade execution to settlement system
├── Settlement system publishes RSA-4096 public key in JWKS
├── Investment bank wraps CEK using RSA-OAEP-256
├── Only settlement system (with private key) can unwrap
├── Multiple parties can encrypt to settlement system (asymmetric distribution)
│
└── No pre-shared secret needed; JWKS is public discovery
```
## Critical Header Parameters (Cryptographic Binding)
### Immutable Authorization Intent
```sh
Scenario: Customer authorizes payment; bank cannot modify terms
├── Customer signs JWS with critical header: `crit: ["amount", "recipient"]`
├── Amount = $1,000, Recipient = "CharityX"
├── JWS header tied to payload (HMAC over header + payload)
├── If bank tries to modify:
│   - amount → signature invalid
│   - recipient → signature invalid
│   - or removes crit parameter → processor rejects
│
└── Signature cryptographically binds to **exact** authorization
```
```java
JWSHeader header = new JWSHeader(JWSAlgorithm.ES256);
header.setCriticalParams(new HashSet<>(Arrays.asList("amount", "recipient")));

JWSObject jws = new JWSObject(
    header,
    new Payload("{\"amount\": 1000, \"recipient\": \"CharityX\", \"crit\": [\"amount\", \"recipient\"]}")
);

ECDSASigner signer = new ECDSASigner(customerEcKey);
jws.sign(signer);

// Bank receives: cannot modify amount or recipient without signature failing
JWSVerifier verifier = new ECDSAVerifier(customerPublicKey);
jws.verify(verifier);  // ← Fails if amount/recipient modified
```

## Replay Attack Prevention (JTI + Expiration)
### Prevent Payment Double-Spending
```sh
Scenario: DDoS attacker captures payment token, replays it 10 times
├── Token includes: jti (unique ID), exp (expiration), nonce
├── System stores: jti_registry = {jti_123, jti_456, ...}
│
├── First request: jti_123 → process payment, store jti_123 in registry
├── Second request (same jti_123):
│   - Check: is jti_123 already in registry?
│   - Yes → REJECT (replay detected)
│   - Fraud alert triggered
│
└── Attacker cannot replay without getting a new token (requires access to signer)
```
```java
JWTClaimsSet claims = new JWTClaimsSet.Builder()
    .subject("customer-789")
    .issuer("bank.example.com")
    .jwtID(UUID.randomUUID().toString())  // ← Unique per token
    .expirationTime(new Date(System.currentTimeMillis() + 300000))  // 5 min
    .build();

SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
jwt.sign(new ECDSASigner(bankKey));

// Receiver-side validation
DefaultJWTProcessor processor = new DefaultJWTProcessor();
processor.setJWSKeySelector(new JWSVerificationKeySelector(JWSAlgorithm.ES256, jwkSource));

try {
    JWTClaimsSet validated = processor.processClaims(jwt);
    String jti = validated.getJWTID();
    
    if (jtiRegistry.contains(jti)) {
        throw new Exception("Replay detected!");  // Fraud
    }
    jtiRegistry.add(jti);  // Register this jti
    
    // Process payment only once
    processPayment(validated);
} catch (BadJWTException e) {
    // Tampering or expiration
}
```

## Key Derivation Functions
### PBKDF2 (Password-Based Key Derivation Function 2)

```sh
Legitimate user: types password once per day
Cost per login: 100ms (acceptable)

Attacker with GPU farm: tries 1 billion passwords/second
Cost per password: 100ms
Time to try 1 billion passwords: 100 million seconds = 3 years
Cost: $100K+ in GPU time (not worth it for single account)
```
`SHA256 is FAST (designed for speed)`

```sh
User enters password: "MyPassword123"

Server does:
  1. Generate random salt: salt = random_16_bytes
  2. Derive key: derived_key = PBKDF2(
       password = "MyPassword123",
       salt = salt,
       iterations = 600000,  ← Makes it expensive!
       hash_function = SHA512
     )
     Result: 0x5a6b7c8d... (64 bytes, takes ~100ms to compute)
  
  3. Store in DB: (salt, derived_key)
       salt        = random_16_bytes
       derived_key = 0x5a6b7c8d...

DB Compromised → Attacker has (salt, derived_key)

Attacker's GPU farm:
  Try password1:
    derived_key1 = PBKDF2(password1, salt, 600000 iterations) → 0xaabbccdd... (100ms)
    Matches stored? No
    
  Try password2:
    derived_key2 = PBKDF2(password2, salt, 600000 iterations) → 0x11223344... (100ms)
    Matches stored? No
    
  Try password3:
    derived_key3 = PBKDF2(password3, salt, 600000 iterations) → 0x5a6b7c8d... (100ms)
    Matches stored? YES!
  
  Speed: 10 attempts per second (because each takes 100ms)
  Time to try 1 billion passwords: 100 million seconds = 3+ years
  
Problem solved: PBKDF2 is SLOW (by design)
```

```sh
U₀ = password  (the user's password)
PRF = HMAC (with password as the key)

# first iteration:
U₁ = HMAC(password, salt)
     ↑         ↑      ↑
     |         |      └─ Input: the salt (random)
     |         └─────── Key: the password
     └─────────────────── HMAC function (using SHA-512)

Result: U₁ = 64 bytes (512 bits) of pseudo-random data

Visual:
  HMAC-SHA512(
    key="MyPassword123",
    message="random_16_bytes"
  ) → U₁ = 0x5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d...

# second iteration:
U₂ = HMAC(password, U₁)
     ↑         ↑     ↑
     |         |     └─ Input: the PREVIOUS output!
     |         └─────── Key: same password
     └─────────────────── HMAC function (using SHA-512)

Result: U₂ = another 64 bytes (looks completely different from U₁)

Visual:
  HMAC-SHA512(
    key="MyPassword123",
    message=U₁  ← Previous output, not the salt!
  ) → U₂ = 0xaabbccddeeff00112233445566778899...

# After 600,000 iterations:
U₁ = HMAC(password, salt)
U₂ = HMAC(password, U₁)
U₃ = HMAC(password, U₂)
U₄ = HMAC(password, U₃)
...
U₆₀₀₀₀₀ = HMAC(password, U₅₉₉₉₉₉)

Each iteration:
  - Takes ~0.167 microseconds (on modern CPU)
  - 600,000 × 0.167 microseconds ≈ 100 milliseconds total  
```
```sh
#Final XOR
After all 600,000 iterations, XOR all results:

DerivedKey = U₁ XOR U₂ XOR U₃ XOR ... XOR U₆₀₀₀₀₀

Why XOR?
  - Combines all 600k iterations into single result
  - If ANY single iteration is compromised, entire output changes
  - Creates dependency chain
  
Result: 
  DerivedKey = 64 bytes (512 bits)
  Looks completely random
  Took 100ms to compute
  Cannot be reversed (HMAC is one-way)
```  

## HKDF (HMAC-Based Key Derivation Function)
```sh
Input:  shared_secret (from ECDH, could be short: 128 bits)
        salt (optional, random)
        info (context: "encryption", "signing", etc.)
        length (desired key length: 256 bits)

Output: derived_key (exactly the requested length)
```
```sh
Same ECDH secret, different purposes:

info = "encryption":
  → produces Encryption_Key (can only encrypt)

info = "authentication":
  → produces Auth_Key (can only authenticate)

info = "signing":
  → produces Signing_Key (can only sign)

Benefit: One ECDH = multiple derived keys, each isolated by info
```
```sh
ECDH Math:
  a = sender's ephemeral private key
  A = a·G (sender's ephemeral public key)
  b = recipient's static private key
  B = b·G (recipient's static public key)

Sender computes:
  shared_secret = a·B = a·(b·G) = (a·b)·G

Recipient computes:
  shared_secret = b·A = b·(a·G) = (a·b)·G
  
Both get SAME shared_secret! (elliptic curve group law)

Then both run HKDF:
  shared_secret → HKDF → CEK (identical on both sides)
```

```sh
Input:
  ECDH produces shared_secret (128-256 bits, possibly non-uniform)
  
HKDF solves:
  1. Expand short secrets to longer keys
  2. Randomize any distribution bias
  3. Derive multiple keys from one secret (with different purposes)
```  
#### The Algorithm (Two Phases)
##### Phase 1: Extract (Compress & Randomize)
```sh
PRK = HMAC(salt, input_key_material)
      ↑     ↑     ↑
      |     |     └─ The weak/short secret (e.g., ECDH result)
      |     └─────── Random value (or empty)
      └───────────── HMAC function

Purpose: Compress input to uniform random bytes
Result: PRK (Pseudo-Random Key) = one HMAC output (e.g., 32 bytes)

Example:
  input_key_material = ECDH result = 0x1a2b3c4d5e6f7a8b9c0d (20 bytes, not enough)
  salt = random_16_bytes (or empty string "")
  
  PRK = HMAC-SHA256(salt, 0x1a2b3c4d5e6f7a8b9c0d)
      = 0x5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b
      (32 bytes, uniform random)
```

#### Phase 2: Expand (Stretch to Desired Length)
```sh
Purpose: Stretch PRK to desired length AND create multiple keys with different purposes

T(0) = empty string

T(1) = HMAC(PRK, T(0) || info || 1)
       ↑     ↑    ↑     ↑    ↑
       |     |    |     |    └─ Counter (ensures different keys)
       |     |    |     └────── Context info ("encryption", "signing", etc.)
       |     |    └──────────── Previous output
       |     └──────────────── PRK from Phase 1
       └──────────────────── HMAC function

T(2) = HMAC(PRK, T(1) || info || 2)
       (Second key for different purpose)

T(3) = HMAC(PRK, T(2) || info || 3)
       (Third key for different purpose)

...

Output Key = T(1) || T(2) || ... || T(n) (truncated to desired length)
```
```sh
ECDH output size = size of the elliptic curve's prime field

Common curves:

P-256 (secp256r1):
  Field: 256-bit prime
  Shared secret: 256 bits (32 bytes)
  
P-384 (secp384r1):
  Field: 384-bit prime
  Shared secret: 384 bits (48 bytes)
  
X25519 (Curve25519):
  Field: 255-bit (actually, 2^255 - 19)
  Shared secret: 256 bits (32 bytes) - padded/formatted
  
secp256k1 (Bitcoin):
  Field: 256-bit prime
  Shared secret: 256 bits (32 bytes)
```  

### Argon2 (Memory-Hard KDF)
```sh
Input:  password
        salt
        memory_cost (256 MB typical)
        time_cost (3 iterations typical)
        parallelism (4 threads typical)

Output: derived_key (resistant to GPU/ASIC attacks)
```
```sh
Attacker wants to crack 1 million passwords:

PBKDF2(600k iterations, CPU-only):
  GPU farm: 1000 GPUs
  Cost: $100K
  Time: 1 year

Argon2(256MB memory, 3 iterations, 4 threads):
  GPU farm: Cannot parallelize (memory bandwidth bottleneck)
  Cost: $1M+ (need memory, not just GPU)
  Time: 10+ years
```
## Key Agreement Based KDFs (Derive from Shared Secret)
### ECDH (Elliptic Curve Diffie-Hellman)
```sh
Curve: y² = x³ + ax + b (over finite field)

Generator G: Known point on curve

Person A's key:
  private: a = random 256-bit number
  public: A = a·G = G + G + ... + G (a times)
         (point multiplication, not arithmetic)

Person B's key:
  private: b = random 256-bit number
  public: B = b·G

ECDH Agreement:
  shared_secret = a·B
               = a·(b·G)
               = (a·b)·G    ← mathematical property
               = (b·a)·G    ← commutativity
               = b·(a·G)
               = b·A        ← Person B computes this

Both compute same point on curve!
```

### ECDH-1PU (Authenticated ECDH)
```sh
Standard ECDH:
  Encryption: ephemeralPrivate · recipientPublic = secret
  Result: Confidential but NO sender authentication

ECDH-1PU:
  Encryption: senderStatic·recipientStatic + ephemeral·recipientStatic
  Result: Confidential AND sender authenticated
 ```
```sh
Problem (Standard ECDH):
  Bank receives encrypted payment
  Message proved: "someone with recipient's pubkey role encrypted this"
  But WHO? Could be attacker, could be customer...

Solution (ECDH-1PU):
  Bank receives encrypted payment
  Message proves: "customer (with THIS specific key) encrypted this"
  Customer authenticated by cryptography, not just token
 ```