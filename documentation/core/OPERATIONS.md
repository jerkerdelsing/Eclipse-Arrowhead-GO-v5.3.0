# Operating the native HTTP profile

## Prerequisites

Prepare separate system certificates/private keys, a trusted CA certificate bundle (never the CA private key), and passwords for each configured system identity. New system server certificates must have CN `<name>.<cloud>.<organization>.arrowhead.eu`, `dnQualifier=sy`, appropriate server/client EKUs and SANs matching their advertised/access addresses. Calling certificates must have `sy` or `op`, the same cloud suffix, and a name matching the identity token. A certificate's `op` qualifier alone does not grant management permission: its verified identity must have sysop privileges or be whitelisted.

Authentication, ServiceRegistry and ConsumerAuthorization outgoing connections are pinned respectively to `Authentication`, `ServiceRegistry`, and `ConsumerAuthorization` in the configured cloud suffix. Ordinary hostname/SAN validation also remains enabled. Do not rename those authorities without deliberately updating and testing the pinning rules.

## Bootstrap

1. Create owner-only password/secret files, outside the tracked repository. Never commit credentials. ConsumerAuthorization requires a stable token secret of at least 32 bytes: losing/changing it invalidates token references and makes persisted encryption keys unreadable.
2. Fill the Authentication template with actual certificate, key, CA, state and bootstrap-password file paths. On an empty identity store, `bootstrapName` (default Sysop) is created with sysop privileges. Bootstrap is not reapplied to a nonempty store. There is no built-in password. Keep a matching client certificate for this bootstrap identity; there is no certificate-name impersonation override.
3. Start Authentication, then log in as the bootstrap identity over mTLS with `POST /authentication/identity/login`. Use `Bearer IDENTITY-TOKEN//<token>` and the matching certificate on management requests.
4. Create identities for ServiceRegistry, ConsumerAuthorization, the selected orchestration system, and service providers/consumers using `POST /authentication/mgmt/identities`. The request is a batch wrapper: `{"authenticationMethod":"PASSWORD","identities":[{"systemName":"ConsumerAuthorization","credentials":{"password":"<your-secret>"},"sysop":false}]}`. Use real secret values through a protected client/request file, not shell history. Create Authentication's own identity too if it will register using password authentication.
5. Set each new process's `name`, `passwordFile`, authority HTTPS URLs and independent `state`. Start ConsumerAuthorization and the chosen orchestrator. Do not give system identities sysop privileges just to bypass missing integration.
6. To use dynamic orchestration, explicitly authorize its identity to use ConsumerAuthorization management check/token-generation operations. This profile only has a whole-management `managementWhitelist`; that broad access is an acknowledged limitation. Configure the registry's `service.discovery.direct.access` for the selected orchestrator so it can discover restricted offers; the orchestrator still applies consumer authorization checks. Do not globally open restricted discovery to work around setup errors.
7. Enable `register` only after bootstrap and set `advertiseAddress`/`advertisePort` to the reachable endpoint. The four new systems register their own system and named service operations, and refresh them every 30 seconds. Fixed origin URLs avoid discovery-based authority substitution. Registration failure does not stop the listener and must be monitored in the process log.

The existing ServiceRegistry has its own startup/self-registration configuration. For outsourced mTLS, it needs its own identity/password, trusted authority registration and the appropriate Authentication service endpoint. Do not share one identity among processes: Authentication intentionally retains only one active session per identity.

## Persistence and shutdown

Use private directories with restrictive permissions and one state file per process. State files are written with mode `0600`; the four new systems lock `<state>.lock`, clone state for each transaction, fsync a temporary snapshot and atomically rename it. A pre-rename failure does not publish the new state. A directory-sync failure after rename reports an error with an uncertain durable commit; verify state before retrying. Do not treat this as a distributed/HA database.

Stop with SIGINT/SIGTERM. The new runtimes stop background registration/push activity and drain requests before releasing state ownership. Existing registrations are not actively revoked on shutdown by the four new systems, so disable/remove stale registrations explicitly during an actual migration. Credentials, CA trust and Java/Go data must be backed up separately and securely; do not copy another cloud's CA private key into this repository or into cross-cloud backups.

## Calls and interfaces

The canonical paths and methods are recorded in `contracts.json`. Service operation names and `generic_https` interface descriptions are defined in `internal/core/registration.go`; service versions are `1.0.0`, system version `5.2.2`. Echo returns plain `Got it!`. Identity management session query is **POST `/authentication/mgmt/sessions`**, not `/sessions/query`.

Simple orchestration does not discover endpoints or issue authorization tokens: like the Java simple variant, it returns store-selected instance identifiers and null endpoint/token fields. Use dynamic orchestration when endpoint/token resolution is required.

HTTPS push callbacks supply `notifyInterface.protocol=HTTPS` and string properties `address`, `port`, `method` (POST/PUT), `path`. The target certificate must match `targetSystemName` in the local cloud. Unrelated callback servers cannot receive result payloads through a trusted-certificate substitution.

The examples are configuration templates, not deployment files. Their illustrative ports are not asserted to be free, and no UI endpoint is introduced by these core systems. LocalCloudManager is a separate support system.
