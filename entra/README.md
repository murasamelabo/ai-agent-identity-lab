# Entra OBO comparison lab

This isolated lab owns **only two new app registrations and their service
principals**. It does not deploy an Azure service, change tenant policies, create
users, modify existing application configurations, or grant Microsoft Graph
permissions. The existing Azure CLI client can receive **per-user consent only
for the new lab API scopes**. No `AllPrincipals` grants are created.

## Safety and scope

- Run only in a tenant where you have explicit authorization. An application
  management directory role is a capability to test, not a policy override.
  `allowedToCreateApps` is read, never changed. Graph refusal immediately stops
  dependent provisioning mutations.
- Uses the existing Azure CLI signed-in user through supported
  `az account get-access-token` commands. No cache scraping, interactive login,
  new Graph scopes, or MFA bypass. Each acquisition has at most two attempts
  across `run` and `resume`; there are no automatic authentication retries.
- Requests both APIs' v2 access-token format. API A is also the confidential
  app-only client, avoiding a third registration.
- Uses one **24-hour secret**, kept only in a user-ACL-protected
  `%LOCALAPPDATA%\Shoten21IdentityLab\<private-run>\state.json`.
  This is deliberately outside the repository and OneDrive. Tokens live only
  in process memory. Azure CLI itself may update its normal supported cache.
- The private state stores exact newly created object IDs, grants, assignments,
  and credential expiry for cleanup. Do not copy it into the repository,
  screenshots, logs, or a publication.
- Only allowlisted claims, aliases, machine error codes, durations and booleans
  go to `reports\comparison.json`. Tenant IDs, object IDs, client IDs, domains,
  names, emails, raw JWTs, credentials, and raw error messages are not exported.
  Exact assigned directory-role names stay private; the report exposes only
  `application_management_role_available`.
  The public, well-known Azure CLI client ID is a code constant, not lab data.
- Local Alice/Bob documents are **synthetic**. Alice's owner is mapped to the
  signed-in user's verified `oid`; Bob is only a local sentinel, not an Entra
  user. App-only access is a separate role-authorized application route and
  never impersonates Alice.

## Reproduce (Windows PowerShell)

The caller must already be signed in to Azure CLI. Do not put tokens, secrets,
private handles or private paths into transcripts/screenshots.

```powershell
Set-Location '.\entra'
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest -v
.\.venv\Scripts\python.exe lab.py probe
.\.venv\Scripts\python.exe lab.py run
.\.venv\Scripts\python.exe lab.py audit
.\.venv\Scripts\python.exe lab.py verify-report
```

`probe` is read-only in Entra; it creates only protected local state.
`run` creates a **new** dedicated lab every time; do not repeat it to retry
authentication. The latest private run is selected automatically.
For an existing fully provisioned run, use:

```powershell
.\.venv\Scripts\python.exe lab.py resume
```

Use `--run <private-run-handle>` only privately when selecting another run.
Never use `resume` to finish refused provisioning; use cleanup instead.
Exit `0` means success (or a completed read-only probe); `2` means blocked/failed.
No raw exception tracebacks or CLI error messages are printed.

On Windows ARM64 a normal pip installation may try to compile `cryptography`
and fail if Visual C++ build tools are unavailable. Do not install compilers
or modify Azure CLI to work around that. If the **existing** Azure CLI-bundled
Python already provides the declared versions, it can run this standalone lab
without installing anything into the CLI distribution:

```powershell
$AzFolder = Split-Path (Get-Command az).Source -Parent
$LabPython = Join-Path (Split-Path $AzFolder -Parent) 'python.exe'
& $LabPython -c "import jwt, cryptography; print(jwt.__version__, cryptography.__version__)"
& $LabPython -m unittest -v
& $LabPython lab.py run
& $LabPython lab.py audit
& $LabPython lab.py verify-report
```

This only reuses an installed Python/library runtime. It does **not** read the
CLI token cache; authentication still uses the supported `az` commands.

### Actual token experiment

1. Azure CLI silently obtains a delegated token for API A (`access_as_user`).
2. Azure CLI silently obtains a direct API B token (`Docs.Read`).
3. API A obtains an API B app-only token (`client_credentials`, `.default`).
4. API A exchanges its input token for API B using
   `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and
   `requested_token_use=on_behalf_of`. **This is not RFC 8693.**
5. Azure CLI requests API B's `Docs.Metadata` scope to observe the actual
   resulting scope set, if silent acquisition succeeds. **Do not assume this
   returns a metadata-only token.**

The script obtains OIDC metadata and issuer JWKS over HTTPS and validates RS256
signature, issuer, intended audience, `exp`, `nbf`, `iat`, tenant and v2 format
before authorizing documents or publishing claims. All three API B tokens
must have the same audience. Compare `scp` versus `roles`, `azp`, `oid`, and
`tid` using the preserved aliases.

The experiment checks delegated Alice success/Bob rejection; app-only access
to both synthetic documents through its separate app-role route; rejection of
an API A token by API B; and rejection of the real OBO `Docs.Read` token by a
metadata route requiring `Docs.Metadata`. The app-only token also cannot use
the delegated document route because it has no `Docs.Read` scope.
`synthetic-documents.json` provides the local documents. These are in-process
resource authorization checks, not a deployed HTTP API or cloud document store.
Offline unit tests use synthetic signatures and are **not** evidence of real
Entra OBO success. `proof_status=partial`/`blocked` is not a successful comparison.
If the first API A silent user acquisition is blocked, dependent direct/OBO
acquisitions are not attempted; the independent app-only acquisition still
provides useful, honestly labeled partial evidence.

The real run observed that Azure CLI returned **both** consented scopes
(`Docs.Read Docs.Metadata`) even when requesting just `Docs.Metadata`.
An initial assumption that this request would create a missing-scope token
was therefore disproved, not hidden. The dedicated missing-scope test uses
the OBO token's **verified** `Docs.Read`-only claim on the metadata route.
The report records both requested and actual issued scope sets.

`audit` performs read-only Graph checks of both applications **and SPs**, full
scope/role definitions and IDs, complete preauthorized scope-ID lists, and exact
required-resource permissions. It enumerates paginated incoming grants and
incoming/outgoing assignments for **both** new resource SPs, and compares the
entire collection with the manifest and private recorded objects. Unknown
grants, `AllPrincipals` consent, extra assignments or definition drift fail the
audit; unknown objects are never deleted. Pagination is same-origin and bounded
to eight pages per collection. It also checks unchanged `allowedToCreateApps`.
It does not acquire more custom API tokens or modify cloud resources.

### Privacy, evidence consistency, and local integrity are different checks

`verify-report` is read-only and reports these three gates separately:

1. **Privacy:** a closed schema rejects unknown fields and string values,
   including unknown aliases/scopes/roles/operations/errors and opaque non-GUID
   identifiers. There is no arbitrary free-text publication field.
2. **Evidence consistency:** validates token audiences/scopes, recalculates
   alias relationships and document authorization outcomes, checks pass flags,
   and requires all expected experiments and exhaustive audit checks for a
   successful complete report. An empty `succeeded` report is not proof.
3. **Local integrity:** the exact canonical report and immutable observation
   digest are bound to the selected private run using HMAC-SHA256. The random
   HMAC key and binding remain only in the ACL-protected private state.
   `audit` verifies the previous binding before writing an updated report.

Report publication journals the known old/new digest and HMAC in private state
before replacing the public report, then finalizes the binding. If either write
fails, recovery accepts **only** a report matching one of those two recorded
bindings. `audit`/`cleanup` finalize that known transition before proceeding;
`verify-report` checks it without rewriting anything. An arbitrary edited
report is never re-signed. A failed public replacement therefore preserves the
old report's usability for exact-known-object cleanup.

This is **not remote attestation** or independent proof of historical JWT
validation. A principal who can modify the private state/code can replace its
local trust baseline. A lost private state/key makes integrity unverifiable;
`verify-report` never silently re-signs or repairs a changed report.

The existing real-token observations predate this integrity mechanism. The
one-time explicit migration command performs a new **read-only audit**, preserves
the earlier token/experiment observations, removes public role names, and binds
the local report **from migration time onward**:

```powershell
python lab.py bind-existing-report
python lab.py verify-report
```

Its public integrity origin is `imported_existing_local_observations`, not a new
token run. It refuses to overwrite an existing binding. Normal new runs create
their local binding automatically; do not use migration to legitimize a
tampered or untrusted report.

### Durable mutation journal

Private JSON writes use a same-directory exclusive sibling, flush, `fsync`,
and atomic replacement. A failed replacement leaves the previous JSON valid.
Before every remote **create**, the exact intended request and full unique run
marker are durably recorded. Newly created applications/SPs carry that full
marker; their names also contain the full run handle, not a prefix-only match.

If a successful response is lost or the follow-up state replacement fails,
dependent mutations stop. Read-only recovery is explicit:

```powershell
python lab.py reconcile
```

Recovery makes bounded exact-name queries and verifies the full marker and
expected properties, or uses already recorded exact resource/client/user/role
relationships. It never enumerates by prefix, retries a create, or deletes a
candidate. Zero or multiple exact matches remain uncertain. A refused request
is not retried. A durably recorded terminal HTTP refusal can be resolved locally
by `reconcile` or `cleanup`: it is archived privately, further provisioning is
disabled for that run, and exact-known-object cleanup is allowed. Timeouts,
transport uncertainty, and legacy refusal records lacking HTTP confirmation
remain blocked pending exact-ownership reconciliation; they are not assumed
to be refusals. A lost `addPassword` response cannot recover its plaintext
secret: only the exact credential metadata can be recorded, and the command
reports `CredentialSecretUnrecoverable` rather than claiming readiness.
Cleanup stops while a mutation outcome remains unresolved.

### Exact-object cleanup

```powershell
.\.venv\Scripts\python.exe lab.py cleanup
```

Cleanup verifies each recorded consent's client/resource/user/scope and each
role assignment's exact endpoints, then deletes only those recorded objects.
It verifies each new application's exact client ID and unique name before
deleting its SP/application. The recorded SP is verified independently even if
the application is already missing. Missing objects are tolerated for retryability.
It never enumerates/deletes arbitrary apps by prefix. It removes the locally
stored secret after successful cleanup, retains a private audit state, and
records sanitized cleanup results in the public report. A failed cleanup
stops rather than widening its target. Deletion is an Entra soft deletion;
the lab does not purge the tenant's deleted-items container.

## Proof and publication

`reports\comparison.json` is the authoritative **actual** run outcome. Only
tokens actually acquired and cryptographically validated are present.
Authentication/Graph failures retain sanitized exact machine error codes, not
tenant/user-bearing descriptions. Screenshot only this report or the
sanitized terminal summary; never a portal page, CLI token command output,
private state, or environment variables. No screenshot is produced by this
script.

## Official sources used

- [Entra OAuth 2.0 OBO flow and input-audience requirement](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
- [Access-token validation and resource-owned format](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [API application: v2 format and preauthorized clients](https://learn.microsoft.com/en-us/graph/api/resources/apiapplication?view=graph-rest-1.0)
- [Per-user delegated grant: `Principal`, `principalId`, SP IDs](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-post?view=graph-rest-1.0)
- [Service principal app-role assignment and required directory roles](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-approleassignments?view=graph-rest-1.0)
