import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign, verify,
} from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import {
  createOwnedContainer, removeOwnedContainer, UnconfirmedContainerOwnershipError,
} from './owned-container.mjs';
import { inspectKeycloakPair, prepareFederatedMcp } from './federated-mcp.mjs';

const VERSION = '26.8.1';
const DIGEST = 'sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244';
const IMAGE = `quay.io/keycloak/keycloak:${VERSION}@${DIGEST}`;
const PORT = Number(process.env.KEYCLOAK_LAB_PORT ?? '18080');
assert(Number.isInteger(PORT) && PORT >= 1024 && PORT <= 65535, 'Invalid lab port');
const BASE = `http://127.0.0.1:${PORT}`;
const REALM = 'idjag-receiver-lab';
const ISSUER = `${BASE}/realms/${REALM}`;
let EXTERNAL_ISSUER = `${BASE}/custom-issuer`;
let externalSubject = 'synthetic-external-user';
const FEDERATED = process.argv.includes('--federated-mcp');
const TOKEN_URL = `${ISSUER}/protocol/openid-connect/token`;
const CLIENT = 'receiver-client';
const JWT_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const IDJAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag';
const TYPE = 'oauth-id-jag+jwt';
const ADMIN_PASSWORD = randomBytes(32).toString('base64url');
const CLIENT_SECRET = randomBytes(32).toString('base64url');
const API_SECRET = randomBytes(32).toString('base64url');
const DISABLED_SECRET = randomBytes(32).toString('base64url');
const UNTRUSTED_SECRET = randomBytes(32).toString('base64url');
const containerName = `shoten-idjag-${randomUUID()}`;
const ownershipNonce = randomUUID();
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const otherKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const publicDerBase64 = publicPem.replace(/-----[^-]+-----|\s/g, '');
const startedAt = new Date().toISOString();
const cases = [];
let containerId;
let resourceServer;
let validAssertion;
let accessToken;
let accessClaims;
let exchangedAccessClaims;
let tokenInspection;
let jwks;
let linkedUserId;
let adminToken;
let report;
let federated;
let unconfirmedContainer;

function docker(args, options = {}) {
  return execFileSync('docker', args, {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...options,
  }).trim();
}

function runOwnershipRegression() {
  const name = `${containerName}-collision-fixture`;
  const nonce = randomUUID();
  let fixtureId;
  try {
    fixtureId = createOwnedContainer(docker, {
      name, nonce, args: ['--label', 'shoten.identity-lab=keycloak-idjag', IMAGE],
    });
    let collidingId;
    assert.throws(() => {
      collidingId = createOwnedContainer(docker, { name, nonce: randomUUID(), args: [IMAGE] });
    }, /already in use/);
    assert.equal(removeOwnedContainer(docker, collidingId, ownershipNonce), false);
    assert.equal(docker(['inspect', '--format', '{{.Id}}', fixtureId]), fixtureId);
    cases.push({ name: 'container_name_collision_preserves_existing_owned_fixture', passed: true });
    console.log('PASS container_name_collision_preserves_existing_owned_fixture');
  } finally {
    if (fixtureId) {
      assert.equal(removeOwnedContainer(docker, fixtureId, nonce), true);
      cases.push({ name: 'collision_fixture_cleanup_uses_verified_exact_id', passed: true });
      console.log('PASS collision_fixture_cleanup_uses_verified_exact_id');
    }
  }
}

async function request(url, { method = 'GET', json, form, bearer } = {}) {
  const headers = {};
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  let body;
  if (json !== undefined) {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(json);
  }
  if (form) {
    headers['content-type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(form).toString();
  }
  const response = await fetch(url, {
    method, headers, body, signal: AbortSignal.timeout(15000),
    redirect: 'error',
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text ? JSON.parse(text) : null,
    location: response.headers.get('location'),
  };
}

async function admin(path, method = 'GET', json) {
  const response = await request(`${BASE}/admin/realms/${path}`, {
    method, json, bearer: adminToken,
  });
  assert(
    response.status >= 200 && response.status < 300,
    `Admin operation ${method} ${path} failed: HTTP ${response.status}`,
  );
  return response;
}

function assertion({ typ = TYPE, claims = {}, omit = [], key = privateKey } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: EXTERNAL_ISSUER,
    sub: externalSubject,
    aud: ISSUER,
    client_id: CLIENT,
    resource: 'lab-api',
    scope: 'lab.read',
    iat: now,
    exp: now + 120,
    jti: randomUUID(),
    ...claims,
  };
  for (const name of omit) delete payload[name];
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const unsigned = `${encode({ alg: 'RS256', typ, kid: 'ephemeral-lab-key' })}.${encode(payload)}`;
  return `${unsigned}.${sign('RSA-SHA256', Buffer.from(unsigned), key).toString('base64url')}`;
}

async function grant(jwt, extra = {}) {
  return request(TOKEN_URL, {
    method: 'POST',
    form: {
      grant_type: JWT_GRANT,
      assertion: jwt,
      client_id: CLIENT,
      client_secret: CLIENT_SECRET,
      scope: 'lab.read',
      ...extra,
    },
  });
}

function record(name, response, expectedStatus, expectedError) {
  assert.equal(response.status, expectedStatus, `${name}: unexpected HTTP status ${response.status}`);
  if (expectedError) assert.equal(response.body.error, expectedError, `${name}: unexpected OAuth error ${response.body.error}`);
  const result = { name, passed: true, http_status: response.status };
  // Only OAuth error identifiers, never raw response bodies or JWTs, enter the report.
  if (response.body?.error) result.oauth_error = response.body.error;
  cases.push(result);
  console.log(`PASS ${name}: HTTP ${response.status}${result.oauth_error ? ` ${result.oauth_error}` : ''}`);
}

function verifyAccessToken(jwt, { audience = 'lab-api' } = {}) {
  assert.equal(jwt.split('.').length, 3);
  const [header64, payload64, signature64] = jwt.split('.');
  const header = JSON.parse(Buffer.from(header64, 'base64url'));
  const claims = JSON.parse(Buffer.from(payload64, 'base64url'));
  assert.equal(header.alg, 'RS256');
  const jwk = jwks.keys.find((key) => key.kid === header.kid && key.kty === 'RSA');
  assert(jwk, 'Unknown signing key');
  assert(verify(
    'RSA-SHA256',
    Buffer.from(`${header64}.${payload64}`),
    createPublicKey({ key: jwk, format: 'jwk' }),
    Buffer.from(signature64, 'base64url'),
  ), 'Bad access token signature');
  assert.equal(claims.iss, ISSUER);
  assert.equal(claims.azp, CLIENT);
  assert.equal(claims.sub, linkedUserId);
  assert(claims.exp > Math.floor(Date.now() / 1000), 'Expired access token');
  if (claims.nbf !== undefined) assert(claims.nbf <= Math.floor(Date.now() / 1000));
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  assert(audiences.includes(audience), 'Wrong resource audience');
  assert((claims.scope ?? '').split(' ').includes('lab.read'), 'Missing resource scope');
  return claims;
}

async function configure() {
  const login = await request(`${BASE}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    form: {
      grant_type: 'password', client_id: 'admin-cli',
      username: 'lab-admin', password: ADMIN_PASSWORD,
    },
  });
  assert.equal(login.status, 200, 'Ephemeral bootstrap login failed');
  adminToken = login.body.access_token;
  await admin('', 'POST', {
    realm: REALM, enabled: true, sslRequired: 'none',
    registrationAllowed: false, accessTokenLifespan: 120,
  });
  await admin(`${REALM}/identity-provider/instances`, 'POST', {
    alias: 'custom-idjag-issuer',
    providerId: 'jwt-authorization-grant',
    enabled: true,
    config: {
      issuer: EXTERNAL_ISSUER,
      jwtAuthorizationGrantEnabled: 'true',
      jwtAuthorizationGrantAssertionReuseAllowed: 'false',
      jwtAuthorizationGrantMaxAllowedAssertionExpiration: '180',
      jwtAuthorizationGrantAssertionSignatureAlg: 'RS256',
      jwtAuthorizationGrantAllowedClockSkew: '0',
      jwtAuthorizationGrantLimitAccessTokenExp: 'true',
      useJwksUrl: 'false',
      publicKeySignatureVerifier: publicDerBase64,
      publicKeySignatureVerifierKeyId: 'ephemeral-lab-key',
    },
  });
  const scopeResponse = await admin(`${REALM}/client-scopes`, 'POST', {
    name: 'lab.read',
    protocol: 'openid-connect',
    attributes: { 'include.in.token.scope': 'true' },
    protocolMappers: [{
      name: 'lab-api-audience',
      protocol: 'openid-connect',
      protocolMapper: 'oidc-audience-mapper',
      config: {
        'included.custom.audience': 'lab-api',
        'access.token.claim': 'true',
        'id.token.claim': 'false',
      },
    }],
  });
  const scopeId = scopeResponse.location.split('/').at(-1);
  await admin(`${REALM}/clients`, 'POST', {
    clientId: 'lab-api', secret: API_SECRET, enabled: true,
    protocol: 'openid-connect', publicClient: false,
    standardFlowEnabled: false, directAccessGrantsEnabled: false,
  });
  for (const [id, secret, enabled, allowed] of [
    [CLIENT, CLIENT_SECRET, 'true', 'custom-idjag-issuer'],
    ['grant-disabled-client', DISABLED_SECRET, 'false', 'custom-idjag-issuer'],
    ['idp-not-allowed-client', UNTRUSTED_SECRET, 'true', ''],
  ]) {
    await admin(`${REALM}/clients`, 'POST', {
      clientId: id, secret, enabled: true, protocol: 'openid-connect',
      publicClient: false, standardFlowEnabled: false,
      directAccessGrantsEnabled: false, serviceAccountsEnabled: false,
      attributes: {
        'oauth2.jwt.authorization.grant.enabled': enabled,
        'oauth2.jwt.authorization.grant.idp': allowed,
        'standard.token.exchange.enabled': 'true',
      },
    });
  }
  const clients = await admin(`${REALM}/clients?clientId=${CLIENT}`);
  await admin(`${REALM}/clients/${clients.body[0].id}/optional-client-scopes/${scopeId}`, 'PUT');
  const createdUser = await admin(`${REALM}/users`, 'POST', {
    username: 'synthetic-reader', enabled: true,
  });
  linkedUserId = createdUser.location.split('/').at(-1);
  await admin(`${REALM}/users/${linkedUserId}/federated-identity/custom-idjag-issuer`, 'POST', {
    identityProvider: 'custom-idjag-issuer',
    userId: externalSubject, userName: 'synthetic-reader',
  });
}

async function runTests() {
  const valid = assertion();
  validAssertion = valid;
  const positive = await grant(valid);
  record('idjag_receiver_accepts_valid_assertion', positive, 200);
  assert.equal(positive.body.refresh_token, undefined, 'JWT grants must not return a refresh token');
  accessToken = positive.body.access_token;
  jwks = (await request(`${ISSUER}/protocol/openid-connect/certs`)).body;
  accessClaims = verifyAccessToken(accessToken);
  tokenInspection = inspectKeycloakPair(validAssertion, accessToken);
  cases.push({ name: 'issued_access_token_signature_issuer_subject_client_audience_scope', passed: true });

  const callerIntrospection = await request(`${ISSUER}/protocol/openid-connect/token/introspect`, {
    method: 'POST',
    form: { token: accessToken, client_id: CLIENT, client_secret: CLIENT_SECRET },
  });
  record('non_audience_client_introspection_reports_inactive', callerIntrospection, 200);
  assert.equal(callerIntrospection.body.active, false, 'Non-audience introspector must not see an active token');
  cases.at(-1).active = false;
  const introspection = await request(`${ISSUER}/protocol/openid-connect/token/introspect`, {
    method: 'POST',
    form: { token: accessToken, client_id: 'lab-api', client_secret: API_SECRET },
  });
  record('resource_audience_access_token_introspection', introspection, 200);
  assert.equal(introspection.body.active, true, 'Introspection: expected active token');
  assert.equal(introspection.body.sub, linkedUserId, 'Introspection: expected linked user');
  assert.equal(introspection.body.client_id ?? introspection.body.azp, CLIENT, 'Introspection: expected receiver client');
  cases.at(-1).active = true;

  const mutations = [
    ['idjag_replay_rejected', valid],
    ['idjag_client_binding_rejected', assertion({ claims: { client_id: 'another-client' } })],
    ['idjag_missing_client_binding_rejected', assertion({ omit: ['client_id'] })],
    ['idjag_missing_iat_rejected', assertion({ omit: ['iat'] })],
    ['idjag_missing_jti_rejected', assertion({ omit: ['jti'] })],
    ['idjag_missing_exp_rejected', assertion({ omit: ['exp'] })],
    ['idjag_wrong_audience_rejected', assertion({ claims: { aud: `${BASE}/wrong-receiver` } })],
    ['idjag_multiple_audiences_rejected', assertion({ claims: { aud: [ISSUER, `${BASE}/other`] } })],
    ['idjag_untrusted_issuer_rejected', assertion({ claims: { iss: `${BASE}/untrusted-issuer` } })],
    ['idjag_unlinked_subject_rejected', assertion({ claims: { sub: 'not-linked' } })],
    ['idjag_untrusted_signing_key_rejected', assertion({ key: otherKey })],
    ['idjag_expired_rejected', assertion({ claims: {
      exp: Math.floor(Date.now() / 1000) - 60, iat: Math.floor(Date.now() / 1000) - 120,
    } })],
    ['idjag_future_nbf_rejected', assertion({ claims: { nbf: Math.floor(Date.now() / 1000) + 60 } })],
    ['idjag_future_iat_rejected', assertion({ claims: { iat: Math.floor(Date.now() / 1000) + 60 } })],
    ['idjag_too_old_iat_rejected', assertion({ claims: { iat: Math.floor(Date.now() / 1000) - 240 } })],
  ];
  for (const [name, jwt] of mutations) {
    const response = await grant(jwt);
    record(name, response, 400);
    assert(response.body.error, `${name}: expected an OAuth error`);
  }
  const invalidCredentials = await grant(assertion(), {
    client_secret: 'deliberately-incorrect-synthetic-secret',
  });
  record('invalid_client_credentials_rejected', invalidCredentials, 401);
  assert(['invalid_client', 'unauthorized_client'].includes(invalidCredentials.body.error));
  for (const [name, clientId, secret] of [
    ['client_grant_disabled_rejected', 'grant-disabled-client', DISABLED_SECRET],
    ['client_issuer_not_allowed_rejected', 'idp-not-allowed-client', UNTRUSTED_SECRET],
  ]) {
    record(name, await grant(assertion({ claims: { client_id: clientId } }), {
      client_id: clientId, client_secret: secret,
    }), 400);
  }

  // Controls: these use the generic RFC 7523 validator, NOT the ID-JAG validator.
  record('rfc7523_plain_jwt_without_client_id_accepted', await grant(assertion({
    typ: 'JWT', omit: ['client_id', 'iat'],
  })), 200);
  record('rfc7523_plain_jwt_mismatched_client_id_accepted', await grant(assertion({
    typ: 'JWT', claims: { client_id: 'another-client' },
  })), 200);
  record('unrecognized_typ_uses_generic_jwt_validator', await grant(assertion({
    typ: 'not-idjag+jwt', omit: ['client_id', 'iat'],
  })), 200);
  // In 26.8.1 maxAllowedAssertionExpiration caps replay-cache lifespan when iat exists.
  // It does NOT reject an otherwise valid assertion merely because exp is farther away.
  record('idjag_long_exp_with_iat_is_accepted_not_a_lifetime_cap', await grant(assertion({
    claims: { exp: Math.floor(Date.now() / 1000) + 600 },
  })), 200);
  record('rfc7523_long_exp_without_iat_rejected', await grant(assertion({
    typ: 'JWT', omit: ['iat'], claims: { exp: Math.floor(Date.now() / 1000) + 600 },
  })), 400);
  const shortExpiry = Math.floor(Date.now() / 1000) + 30;
  const shortGrant = await grant(assertion({ claims: { exp: shortExpiry } }));
  record('receiver_access_token_exp_limited_by_assertion', shortGrant, 200);
  const shortClaims = verifyAccessToken(shortGrant.body.access_token);
  assert(shortClaims.exp <= shortExpiry, 'Access token must not outlive assertion');

  for (const [name, tokenType, expectedStatus] of [
    ['rfc8693_access_token_exchange_control', ACCESS_TOKEN_TYPE, 200],
    ['native_idjag_issuance_via_rfc8693_not_supported', IDJAG_TOKEN_TYPE, 400],
  ]) {
    const exchanged = await request(TOKEN_URL, {
      method: 'POST',
      form: {
        grant_type: EXCHANGE,
        subject_token: accessToken,
        subject_token_type: ACCESS_TOKEN_TYPE,
        requested_token_type: tokenType,
        client_id: CLIENT,
        client_secret: CLIENT_SECRET,
        scope: 'lab.read',
      },
    });
    if (tokenType === ACCESS_TOKEN_TYPE) {
      assert.equal(exchanged.status, 200, 'RFC 8693 exchange must succeed');
      assert.equal(typeof exchanged.body.access_token, 'string', 'Exchange must return an access token');
      assert(exchanged.body.access_token.length > 0, 'Exchanged access token must be nonempty');
      assert.equal(exchanged.body.issued_token_type, ACCESS_TOKEN_TYPE, 'Unexpected exchanged token type');
      assert.equal(exchanged.body.token_type, 'Bearer', 'Unexpected exchanged token presentation type');
      exchangedAccessClaims = verifyAccessToken(exchanged.body.access_token);
      record(name, exchanged, expectedStatus);
      cases.at(-1).issued_token_type = exchanged.body.issued_token_type;
      cases.at(-1).signature_issuer_subject_client_audience_scope_verified = true;
    } else {
      assert.equal(exchanged.status, expectedStatus, 'ID-JAG issuance must reject unsupported token type');
      assert.match(exchanged.body.error_description ?? '', /requested_token_type|token type/i);
      record(name, exchanged, expectedStatus);
      cases.at(-1).verified_reason = 'unsupported requested token type';
    }
  }

  resourceServer = createServer((req, res) => {
    if (req.method !== 'GET' || req.url !== '/resource') {
      res.writeHead(404).end();
      return;
    }
    try {
      const bearer = req.headers.authorization;
      assert(bearer?.startsWith('Bearer '));
      verifyAccessToken(bearer.slice(7));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ result: 'synthetic protected resource' }));
    } catch {
      res.writeHead(401, {
        'content-type': 'application/json',
        'www-authenticate': 'Bearer error="invalid_token"',
      });
      res.end(JSON.stringify({ error: 'invalid_token' }));
    }
  });
  await new Promise((resolve, reject) => {
    resourceServer.once('error', reject);
    resourceServer.listen(0, '127.0.0.1', resolve);
  });
  const resourceUrl = `http://127.0.0.1:${resourceServer.address().port}/resource`;
  record('resource_accepts_receiver_access_token', await request(resourceUrl, { bearer: accessToken }), 200);
  record('resource_rejects_identity_assertion_as_bearer', await request(resourceUrl, { bearer: assertion() }), 401);
  record('resource_rejects_missing_token', await request(resourceUrl), 401);
  assert.throws(() => verifyAccessToken(accessToken, { audience: 'another-api' }));
  cases.push({ name: 'resource_audience_validation_rejects_another_api', passed: true });
}

try {
  console.log(`Starting isolated localhost-only Keycloak ${VERSION}`);
  docker(['image', 'inspect', IMAGE]);
  if (FEDERATED) {
    federated = await prepareFederatedMcp({ receiverIssuer: ISSUER, privateKey, publicKey });
    await federated.start();
    EXTERNAL_ISSUER = federated.issuer;
    externalSubject = federated.subject;
    console.log('Real Entra own-API user token verified in memory; custom local broker and MCP server started.');
  }
  runOwnershipRegression();
  containerId = createOwnedContainer(docker, {
    name: containerName, nonce: ownershipNonce,
    args: [
    '--label', 'shoten.identity-lab=keycloak-idjag',
    '--publish', `127.0.0.1:${PORT}:8080`,
    '--env', 'KC_BOOTSTRAP_ADMIN_USERNAME=lab-admin',
    '--env', 'KC_BOOTSTRAP_ADMIN_PASSWORD',
    '--env', 'KC_HTTP_ACCESS_LOG_ENABLED=false',
    IMAGE, 'start-dev',
    '--features=jwt-authorization-grant,identity-assertion-jwt,token-exchange-standard',
    '--hostname', BASE,
    ],
    options: { env: { ...process.env, KC_BOOTSTRAP_ADMIN_PASSWORD: ADMIN_PASSWORD } },
  });
  console.log(`Owned container: ${containerName} (${containerId.slice(0, 12)})`);
  docker(['start', containerId]);
  let ready = false;
  const deadline = Date.now() + 180000;
  while (Date.now() < deadline) {
    try {
      const response = await request(`${BASE}/realms/master/.well-known/openid-configuration`);
      if (response.status === 200) { ready = true; break; }
    } catch { /* Startup connection failures are expected until the readiness deadline. */ }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  assert(ready, 'Keycloak did not become ready within 180 seconds');
  const actualVersion = docker(['exec', containerId, '/opt/keycloak/bin/kc.sh', '--version']);
  assert(actualVersion.includes(VERSION), 'Unexpected Keycloak version');
  await configure();
  if (federated) {
    await federated.configureReceiver(admin, linkedUserId);
    const result = await federated.execute();
    report = {
      ...result, started_at: startedAt, completed_at: new Date().toISOString(),
      runtime: { node: process.version, keycloak: VERSION, image_digest: DIGEST },
      tests: [...cases, ...result.tests],
    };
  } else {
  await runTests();
  report = {
    schema: 'shoten.keycloak-idjag-receiver-results.v1',
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    runtime: { node: process.version, keycloak: VERSION, image_digest: DIGEST },
    configuration: {
      receiver: ISSUER,
      external_issuer: EXTERNAL_ISSUER,
      issuer_implementation: 'custom in-process fixture signer; no issuer HTTP service or user login',
      assertion_typ: TYPE,
      enabled_features: ['jwt-authorization-grant', 'identity-assertion-jwt', 'token-exchange-standard'],
      trust: 'explicit static ephemeral RSA public key, exact issuer, client allowlist, linked subject',
      assertion_lifetime_seconds: 120,
      configured_max_allowed_assertion_expiration_seconds: 180,
      replay_allowed: false,
      network_binding: `127.0.0.1:${PORT}`,
    },
    verified_access_token_context: {
      signature_verified_with_receiver_jwks: true,
      issuer: accessClaims.iss,
      subject: '<linked-local-user>',
      authorized_party: accessClaims.azp,
      audience: accessClaims.aud,
      scope: accessClaims.scope,
    },
    verified_exchanged_access_token_context: {
      signature_verified_with_receiver_jwks: true,
      issued_token_type: ACCESS_TOKEN_TYPE,
      issuer: exchangedAccessClaims.iss,
      subject: '<linked-local-user>',
      authorized_party: exchangedAccessClaims.azp,
      audience: exchangedAccessClaims.aud,
      scope: exchangedAccessClaims.scope,
    },
    token_inspection: tokenInspection,
    tests: cases,
    passed: cases.every((test) => test.passed),
    limitations: [
      'Experimental Keycloak ID-JAG receiver based on its documented draft-01; not a conformance certification.',
      'Custom signer creates synthetic fixtures, not an enterprise IdP or native Keycloak ID-JAG issuer.',
      'RFC 7523 is separately accepted; unrecognized typ dispatches to generic validation.',
      'The configured maxAllowedAssertionExpiration limits iat age and replay-cache lifespan, not exp minus iat. Main fixtures expire in 120 seconds, below the configured 180 seconds.',
      'No OIDC authorization-code login, ID-token-to-ID-JAG exchange, MCP protocol, or full MCP EMA flow.',
      'Resource is a minimal HTTP JWT verifier, not an MCP server.',
      'HTTP and bootstrap password grant are local-only development conveniences, not production guidance.',
      'Single-node replay tests do not certify cluster, restart, or concurrent replay behavior.',
    ],
  };
  }
} catch (error) {
  if (error instanceof UnconfirmedContainerOwnershipError) {
    unconfirmedContainer = {
      container_id: error.containerId, expected_owner_label: error.ownershipLabel,
      expected_owner_nonce: error.ownershipNonce, manual_recovery_required: true,
      automatic_removal_attempted: false,
    };
  }
  // Avoid serializing fetch responses, JWTs, Docker environments or command arguments.
  console.error(`LAB FAILED: ${error instanceof Error ? error.message.split('\n')[0] : 'unknown failure'}`);
  process.exitCode = 1;
  if (FEDERATED) {
    const safeBlockers = new Set([
      'EntraPrivateStateUnavailable', 'EntraSilentTokenUnavailable',
      'EntraMetadataOrKeysUnavailable', 'EntraUserTokenValidationFailed',
    ]);
    report = {
      schema: 'shoten.entra-custom-broker-keycloak-mcp-results.v1',
      proof_status: 'blocked', passed: false, started_at: startedAt,
      completed_at: new Date().toISOString(),
      blocker: safeBlockers.has(error?.message) ? error.message : 'FederatedPrototypeFailed',
      tests: [...cases, ...(federated?.tests ?? [])],
    };
  }
} finally {
  let localServersClosed = true;
  if (federated) {
    try { await federated.close(); } catch {
      localServersClosed = false;
      process.exitCode = 1;
      console.error('Loopback server cleanup failed.');
    }
  }
  if (resourceServer) await new Promise((resolve) => resourceServer.close(resolve));
  let removed = false;
  if (containerId) {
    try {
      removed = removeOwnedContainer(docker, containerId, ownershipNonce);
      console.log(`Removed owned container: ${containerName} (${containerId.slice(0, 12)})`);
    } catch {
      console.error(`Cleanup not performed: verify ID=${containerId} and expected shoten.identity-lab.owner=${ownershipNonce} before manual recovery.`);
      process.exitCode = 1;
    }
  } else if (process.exitCode) {
    console.error('No positively-owned main container ID was obtained; no cleanup by container name was attempted.');
  }
  if (report) {
    report.passed &&= removed && localServersClosed;
    report.cleanup = {
      container_name: containerName, ...(containerId ? { container_id: containerId } : {}),
      removed, local_servers_closed: localServersClosed,
      ...(unconfirmedContainer ? { unconfirmed_created_container: unconfirmedContainer } : {}),
      services_left_running: (Boolean(containerId) && !removed) || !localServersClosed || Boolean(unconfirmedContainer),
    };
    const directory = fileURLToPath(new URL('./results/', import.meta.url));
    mkdirSync(directory, { recursive: true });
    const filename = FEDERATED ? 'federated-mcp-results.json' : 'verified-results.json';
    writeFileSync(new URL(`./results/${filename}`, import.meta.url), `\uFEFF${JSON.stringify(report, null, 2)}\n`, 'utf8');
    console.log(`Publication-safe results: ${directory}${filename}`);
  }
}
