# Security boundaries

The four new runtimes require mTLS and verify local-cloud CN/profile plus identity-token binding. Outbound authority pinning happens in TLS verification, before sending passwords or token-bearing requests. Redirects are rejected. Authentication refresh is mutex-coalesced and invalidates only the rejected cached token, preventing an old in-flight 401 from invalidating a newly refreshed token.

Passwords use bcrypt cost 10; password hashing rejects empty and over-72-byte inputs. Login rotates the sole session of an identity; logout/change use credentials, not a user-supplied token selector. Identity tokens are UUIDv4 and are stored only as SHA-256 references. Verification of unknown/expired sessions returns a false result rather than inventing an identity.

Authorization defaults to deny, MGMT decisions override provider decisions, and online token verification is provider-bound. Usage decrements are transactional. Self-contained tokens cannot be verified using the opaque-token verification endpoint. JWT signatures use the configured RSA server key (RS256/RS512), not an unrelated generated key. Token references use HMAC-SHA256; provider encryption keys use AES-GCM at rest with provider identity binding. Raw generated tokens are not retained.

Legacy AES-ECB and fixed-provider-IV AES-CBC are implemented **only for Java wire compatibility**. They do not provide authenticated encryption for the transmitted token; prefer signed JWTs with appropriate provider verification, and do not infer modern cryptographic guarantees from these legacy encryption variants. AES-GCM protects the stored encryption keys, not the legacy wire ciphertext.

Management requires a verified sysop identity or an explicit management whitelist. Whitelisting grants broad management access, not per-operation least privilege. Do not expose these processes directly to untrusted networks or use that whitelist to bypass fine-grained authorization requirements.

Audit logs omit request bodies, credentials and actual token-bearing URL parameters; they use route templates. Configuration responses exclude secret material and private-key paths. The trusted CA bundle contains certificates only. No CA key is required by the implementation. Tests generate their own short-lived CA and do not read cloud private keys.

Revocation: client and authority certificates of the cloud CA are checked against its CRL (`crlFile`, ServiceRegistry `server.ssl.crl-file`) on every handshake, failing closed without a current CRL; there is no OCSP. Important residual risks: no rate limiting, blacklist integration, HA, automatic retention or production penetration test; process-owner access can read state and configured secrets. Offline token verification must enforce signature, issuer, provider/consumer/target/scope, expiry and appropriate revocation policy at the provider. Backup and secret-file handling remain operational responsibilities. See `COMPATIBILITY.md` for integration gaps that block general cloud interchangeability.

This source delivery does not remediate previously reported live-cloud CA backup leakage, stale deployed images, Go dependency advisories, cross-port UI cookies, or federation end-to-end security. Those require separate deployment/evaluation work.
