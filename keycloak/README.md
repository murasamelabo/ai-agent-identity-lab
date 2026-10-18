# Keycloak ID-JAG receiver: localhost protocol lab

The default mode is a **real Keycloak receiver protocol experiment**, not a simulated response
and not an end-to-end MCP Enterprise-Managed Authorization (EMA) implementation.
It uses no Entra resources. No Entra OBO operation is demonstrated or inferred.

**Optional federated mode:** [FEDERATED.md](FEDERATED.md) documents a separately
tested real Entra own-API user token → **custom** local broker issuing ID-JAG →
native Keycloak receiver → protected MCP 2025-11-25 tools/list/tools/call path.
It is a verified prototype core flow, **not** native Entra ID-JAG or stable EMA
conformance. Run it only with the explicit prerequisites/authorization there.

## Pinned official release

- Keycloak **26.8.1**, published **2026-10-13**, inspected on 2026-10-18.
- Official image:
  `quay.io/keycloak/keycloak:26.8.1@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244`
- Enabled features:
  `jwt-authorization-grant,identity-assertion-jwt,token-exchange-standard`.
- In the pinned feature registry, `jwt-authorization-grant` is `DEFAULT`;
  `identity-assertion-jwt` is `EXPERIMENTAL`. They are not the same maturity level.
- Keycloak's tagged ID-JAG guide calls the receiver **experimental**, references
  `draft-ietf-oauth-identity-assertion-authz-grant-01`, and explicitly says native
  ID-JAG **issuer support is not implemented**.

Do not replace the pinned tag/digest with `latest` when reproducing these results.
This is evidence about this release, not a statement that every later draft's
requirement is implemented.

## Run (PowerShell, Windows, Docker Desktop Linux containers and Node.js 22+)

From the repository root:

```powershell
Set-Location keycloak
docker pull quay.io/keycloak/keycloak:26.8.1@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244
node --check run.mjs
node --test owned-container.test.mjs
node run.mjs
Get-Content -Raw -Encoding utf8 results\verified-results.json
```

There are **zero npm dependencies**; neither `npm install` nor a virtual
environment is needed. `npm test` also runs `node run.mjs`.
`package.json` documents the runtime and commands.

Port 18080 must be free. To choose another loopback port:

```powershell
$env:KEYCLOAK_LAB_PORT = '18081'
node run.mjs
Remove-Item Env:\KEYCLOAK_LAB_PORT
```

Every run creates its **own** named container, fresh realm, randomly generated
admin/client secrets, and a new RSA key pair. It does not attach existing Docker
volumes or interact with other containers. All private keys and credentials exist
only in process/container memory and the disposable container's writable layer.
No secrets, raw assertions, access tokens, or real identities are written to the
repository or the report. The custom fixture signer is **not Entra**, not an
enterprise IdP, and not a native Keycloak issuer. It does not expose an issuer
HTTP service or perform a user login.

Containers are first **created**, yielding a full immutable container ID, then
started by that ID. A random per-run ownership nonce is attached as a Docker
label. Cleanup checks the full ID and nonce before removing only that ID; a name
collision never authorizes adoption or removal of the pre-existing container.
If creation or ownership confirmation fails before an ID is returned, the runner
does not attempt cleanup by name and surfaces the failure instead.
If Docker created a full ID but subsequent inspection failed, a dedicated
`UnconfirmedContainerOwnershipError` preserves the full ID, expected ownership
label/nonce, and original cause. Its single-line message surfaces the ID and
nonce even though the container is deliberately not adopted or automatically
removed. The nonce is an ownership marker, not a credential.

`finally` removes the verified owned container and closes the temporary resource
server. If interrupted before cleanup, verify ownership first and use only the
exact full container ID printed/recorded by that successful creation:

```powershell
docker inspect --format '{{.Id}} {{index .Config.Labels "shoten.identity-lab.owner"}}' <exact-owned-container-id>
# Proceed only if both the full ID and nonce match the recorded values.
docker rm --force <exact-owned-container-id>
```

Do not remove containers by broad name patterns. Docker Desktop and the pulled
image remain installed; no lab service should remain running after a normal run.

The six dependency-free ownership unit tests simulate collisions, invalid IDs,
mismatched nonce labels, and inspection failure after creation without contacting
Docker. The inspection-failure regression checks recovery metadata/message and
proves no removal occurs. The integration suite
also creates its own stopped, portless fixture, deliberately collides with its
name under a different nonce, verifies that the fixture survives, and removes
only its verified original ID. It does not use an unrelated container for this
regression.

## Endpoints while the script is running

| Component | Local endpoint |
| --- | --- |
| Isolated Keycloak | `http://127.0.0.1:18080` |
| Receiver realm issuer | `http://127.0.0.1:18080/realms/idjag-receiver-lab` |
| Receiver token endpoint | `http://127.0.0.1:18080/realms/idjag-receiver-lab/protocol/openid-connect/token` |
| Receiver JWKS | `http://127.0.0.1:18080/realms/idjag-receiver-lab/protocol/openid-connect/certs` |
| Introspection | `http://127.0.0.1:18080/realms/idjag-receiver-lab/protocol/openid-connect/token/introspect` |
| Synthetic issuer claim (not a running endpoint) | `http://127.0.0.1:18080/custom-issuer` |
| Minimal protected HTTP resource | `http://127.0.0.1:<OS-assigned-loopback-port>/resource` |

Only Docker's host port bound to **127.0.0.1** is published. The resource binds
127.0.0.1 too. No screenshots or diagram files are generated.
The public `verified-results.json` is intended for a parent-generated publication
dashboard; it contains the exact local receiver endpoint and sanitized outcomes.

## What crosses each trust boundary

1. The custom signer creates a synthetic external identity assertion with RS256,
   `typ=oauth-id-jag+jwt`, trusted `iss`, linked `sub`, one receiver `aud`,
   `iat`, `exp`, unique `jti`, and receiver-registered `client_id`.
2. The receiver trusts the signer's **explicitly configured ephemeral public
   key**, not a self-declared issuer URL. The Keycloak provider is
   `jwt-authorization-grant`; its issuer matches the assertion exactly.
3. The confidential client has grant enablement and an explicit IdP allowlist:
   `oauth2.jwt.authorization.grant.enabled=true` and
   `oauth2.jwt.authorization.grant.idp=custom-idjag-issuer`.
4. Keycloak links the external subject to a pre-created local synthetic user.
   This lab tests an existing mapping, not automatic just-in-time provisioning.
5. The client sends `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`,
   `assertion`, `client_id`, `client_secret`, and `scope=lab.read` to Keycloak.
   The ID-JAG-specific validator binds the asserted client to the authenticated
   client, requires `iat`, and prohibits assertion reuse.
6. Keycloak returns its **own access token**. The runner verifies its RS256
   signature against Keycloak's JWKS and checks receiver `iss`, local user `sub`,
   `azp=receiver-client`, `aud=lab-api`, expiration, and `scope=lab.read`.
7. A minimal HTTP resource independently applies those checks. It accepts that
   access token, but rejects the external identity assertion as a bearer token.
   The resource is not an MCP server.

`jwtAuthorizationGrantLimitAccessTokenExp=true` prevents the receiver access
token from outliving the assertion. The realm also uses a 120-second access-token
lifetime. Main assertion fixtures expire after 120 seconds.

## Do not conflate these protocols

| Mechanism | Request / role in this lab | Honest interpretation |
| --- | --- | --- |
| RFC 7523 JWT authorization grant | `grant_type=...:jwt-bearer`, `assertion=...`; plain `typ=JWT` controls | A signed JWT grant does not by itself prove ID-JAG |
| ID-JAG receiver | Same RFC 7523 grant, but `typ=oauth-id-jag+jwt` selects the feature's validator; specific claims/client binding/replay checks | Real experimental native Keycloak receiver behavior, with a custom fixture issuer |
| RFC 8693 token exchange | `grant_type=...:token-exchange`, `subject_token`, explicit `subject_token_type` / `requested_token_type` | A separate protocol; ordinary access-token exchange is a control, not ID-JAG issuance |
| MCP EMA | Would additionally need faithful enterprise issuer authorization, discovery/trust setup, identity-token-to-ID-JAG issuance and MCP client/server interactions | **Not implemented, not tested end-to-end** |
| Entra OBO | Would require an authorized Entra tenant/application setup | **Not tested**; the lab must not be presented as Entra evidence |

The generic JWT controls deliberately omit `client_id` / `iat`, or carry a
mismatched `client_id`. Their acceptance contrasts with ID-JAG rejection.
The release dispatches an unrecognized `typ` to the **generic** validator too;
therefore this configuration is not an “ID-JAG-only” allowlist.

The positive RFC 8693 control requires a nonempty returned `access_token`,
`issued_token_type=urn:ietf:params:oauth:token-type:access_token`, and
`token_type=Bearer`. Before marking that control as passed, it independently
verifies the **exchanged** token's RS256 signature against the receiver JWKS,
issuer, linked subject, authorized client, resource audience, scope, and time
claims. An HTTP 200 alone is insufficient. Only the sanitized context enters
`verified_exchanged_access_token_context` in the result JSON.

### Expiration option nuance

Do **not** describe
`jwtAuthorizationGrantMaxAllowedAssertionExpiration=180` as a universal
`exp - iat <= 180` limit. The tagged validator checks assertion age against `iat`
and caps the single-use cache lifespan; with `iat` present, a farther-away `exp`
is not itself rejected. Without `iat`, a plain JWT with too-distant `exp` is
rejected. The suite records this distinction. Normal fixtures have a 120-second
expiration, within the configured 180-second window. The immediate replay test
does not certify replay behavior across restarts, clusters, or concurrent races.

### Introspection audience nuance

In 26.8.1, introspecting as `receiver-client` reports `active=false` when that
client is absent from the token's audiences; this is not proof that the signed
token is universally inactive. Authenticating the introspection request as `lab-api`
returns `active=true`. The suite tests both and does not disable audience checks.
The verified run includes the realm's standard scopes as well as `lab.read`;
its access-token audiences are `lab-api` and `account`. The assertion's required
single receiver audience and an access token's resource audiences are different
contexts; the report preserves the observed access-token values.

## Evidence and failure behavior

`results\verified-results.json` is generated **only after every assertion in the
suite passes**, includes the runtime version, pinned image digest, successful
positive/negative/control tests, limitations, and exact cleanup outcome.
The report substitutes `<linked-local-user>` for the random internal user UUID.
No result is a mock and no raw JWT is included.

The checked-in run on **2026-10-18** passed **36 integration checks**, using
Node.js **v24.18.0** and the pinned Keycloak image. The six ownership unit tests
also passed. Its owned container
`shoten-idjag-87c11961-3ad3-412a-93a8-4421df767685` (`96f3778c7559`) and its
stopped collision fixture were removed; no lab service was left running. A later
run overwrites the JSON with its own timestamps and container ID.

`PASS` means a real observed HTTP status (and, where specified, OAuth error)
matched the test expectation. Successful signature and claim checks have their
own non-HTTP result. Negative assertion requests are expected to fail; a 400 is
not a failure of the test itself.

On startup/protocol failure the runner exits nonzero, still removes its owned
container, and does not publish a new successful report. An older report's
timestamp is not evidence of a later failed run. A test that newly fails after
changing Keycloak must be investigated, not relabeled to manufacture success.

## Official, version-pinned evidence

- [26.8.1 release](https://github.com/keycloak/keycloak/releases/tag/26.8.1)
- [ID-JAG guide: experimental receiver, draft-01, no native issuer](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/securing-apps/identity-assertion-jwt-authorization-grant.adoc)
- [JWT authorization grant guide](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/securing-apps/jwt-authorization-grant.adoc)
- [Feature/type dispatch in JWTAuthorizationGrantType](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/grants/JWTAuthorizationGrantType.java)
- [ID-JAG client binding, required iat, no reuse](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/grants/IDJWTAuthorizationGrantValidator.java)
- [Base signature/audience/time/single-use validation](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/authentication/authenticators/client/AbstractBaseJWTValidator.java)
- [Provider configuration attributes](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/broker/jwtauthorizationgrant/JWTAuthorizationGrantConfig.java)
- [Introspection audience validation](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/AccessTokenIntrospectionProvider.java)
- [Official ID-JAG tests](https://github.com/keycloak/keycloak/blob/26.8.1/tests/base/src/test/java/org/keycloak/tests/oauth/IDJWTAuthorizationGrantTest.java)
- [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)

The local experiment implements original test code; it does not copy Keycloak
implementation source or claim vendor certification.
