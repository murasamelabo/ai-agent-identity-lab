import assert from 'node:assert/strict';
import test from 'node:test';
import {
  FEDERATED_CHECKS, KEYCLOAK_CHECKS, assertPublishableLines, createRecorder, diffAssertion, layout, parseKeycloakLog,
  renderFederatedView, renderKeycloakView, safeText, sensitiveReason, TRACE_SCHEMA,
} from './trace.mjs';

const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const fakeJwt = (header, claims) => `${encode(header)}.${encode(claims)}.${'S'.repeat(86)}`;
const TENANT = '11111111-2222-3333-4444-555555555555';
const NOW = Math.floor(Date.now() / 1000);

function idjag(overrides = {}) {
  return fakeJwt({ alg: 'RS256', typ: 'oauth-id-jag+jwt', kid: 'ephemeral-lab-key' }, {
    iss: 'http://127.0.0.1:18080/custom-issuer', sub: 'synthetic-external-user',
    aud: 'http://127.0.0.1:18080/realms/idjag-receiver-lab', client_id: 'receiver-client', resource: 'lab-api',
    scope: 'lab.read', iat: NOW, exp: NOW + 120, jti: 'secret-jti-value', ...overrides,
  });
}

test('safeText keeps lab identifiers and rejects token-like, GUID-like and e-mail content', () => {
  assert.equal(safeText('urn:ietf:params:oauth:grant-type:jwt-bearer'), 'urn:ietf:params:oauth:grant-type:jwt-bearer');
  assert.equal(safeText('synthetic-reader@example.test'), 'synthetic-reader@example.test');
  assert.equal(safeText(idjag()), '<omitted>');
  assert.equal(safeText(TENANT), '<omitted>');
  assert.equal(safeText('someone@contoso.com'), '<omitted>');
  assert.equal(safeText('Zk3tQ8vN1xYp0LmA7sD2fG5hJ9bC4eR6uT1wV8yXzAa'), '<omitted>');
  assert.equal(sensitiveReason('real_entra_user_signature_issuer_audience_expiry_scope_verified'), null);
  assert.equal(safeText('x'.repeat(300), 20).length, 20);
});

test('layout wraps tokens on the given width and keeps a continuation indent', () => {
  assert.deepEqual(layout(['aaaa', 'bbbb', 'cccc'], '  ', { first: '> ', width: 12 }), ['> aaaa  bbbb', '  cccc']);
});

test('recorder masks identities, summarizes tokens and never stores raw token material', () => {
  const recorder = createRecorder();
  recorder.reset();
  recorder.mask(TENANT, '[TENANT_ID]');
  recorder.origin('http://127.0.0.1:18080', 'keycloak');
  const assertion = idjag();
  const access = fakeJwt({ alg: 'RS256', typ: 'JWT', kid: 'realm-key' }, {
    iss: 'http://127.0.0.1:18080/realms/idjag-receiver-lab', sub: '00000000-0000-0000-0000-000000000001', aud: ['lab-api', 'account'],
    azp: 'receiver-client', typ: 'Bearer', scope: 'lab.read', iat: NOW, exp: NOW + 120, jti: 'secret-access-jti', email: 'secret@contoso.com',
  });
  const index = recorder.http({
    method: 'POST', url: `http://127.0.0.1:18080/realms/idjag-receiver-lab/protocol/openid-connect/token?tenant=${TENANT}`,
    form: { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion, client_id: 'receiver-client', client_secret: 'very-secret-value' },
    status: 200, body: { access_token: access, expires_in: 120, token_type: 'Bearer', scope: 'lab.read' },
  });
  recorder.name(index, 'idjag_receiver_accepts_valid_assertion');
  const entry = recorder.entries[index];
  assert.equal(entry.target, 'keycloak');
  assert.deepEqual(entry.request.form.find(([name]) => name === 'client_secret'), ['client_secret', '<redacted>']);
  assert.match(entry.request.form.find(([name]) => name === 'assertion')[1], /^<JWT \d+ chars>$/);
  assert.equal(entry.request.tokens[0].summary.claims.jti, '[REDACTED]');
  assert.equal(entry.response.tokens[0].summary.claims.sub, '[LINKED_LOCAL_USER]');
  assert.equal(entry.response.tokens[0].summary.claims.email, undefined);
  assert.deepEqual(entry.response.fields.at(-1), ['refresh_token', '(absent)']);
  const trace = recorder.finalize();
  const serialized = JSON.stringify(trace);
  for (const secret of ['very-secret-value', 'secret-jti-value', 'secret-access-jti', 'secret@contoso.com', TENANT, assertion.split('.')[1], access.split('.')[1]]) {
    assert(!serialized.includes(secret), `leaked ${secret}`);
  }
  assert.equal(trace.schema, TRACE_SCHEMA);
});

test('finalize refuses a trace that still contains a known identifier', () => {
  const recorder = createRecorder();
  recorder.reset();
  recorder.mask(TENANT, '[TENANT_ID]');
  recorder.local({ name: 'leaky', outcome: 'ok', detail: 'detail without the identifier' });
  recorder.entries[0].detail = `tenant ${TENANT}`;
  assert.throws(() => recorder.finalize(), /TraceContainsKnownIdentifier/);
});

test('assertion diff names only the claims that differ from the valid token', () => {
  const recorder = createRecorder();
  recorder.reset();
  const base = recorder.token(idjag(), 'idjag');
  assert.equal(diffAssertion(base, recorder.token(idjag(), 'idjag')), '');
  assert.equal(diffAssertion(base, recorder.token(idjag({ client_id: 'another-client' }), 'idjag')), 'client_id: receiver-client -> another-client');
  assert.equal(diffAssertion(base, recorder.token(idjag({ exp: NOW - 60, iat: NOW - 120 }), 'idjag')), 'iat: now -> now-120s; exp: now+120s -> now-60s');
  const missing = JSON.parse(Buffer.from(idjag().split('.')[1], 'base64url'));
  delete missing.jti;
  assert.equal(diffAssertion(base, recorder.token(fakeJwt({ alg: 'RS256', typ: 'oauth-id-jag+jwt' }, missing), 'idjag')), 'jti: removed');
});

test('Keycloak log parser keeps only the realm events and attaches them to the matching request', () => {
  const log = [
    '2026-11-02 12:17:25,058 INFO  [org.keycloak.http.access-log] (executor-thread-1) 172.17.0.1 - - [02/Nov/2026:12:17:25 +0000] "GET /realms/master/.well-known/openid-configuration HTTP/1.1" 200 6586',
    '2026-11-02 12:17:26,764 DEBUG [org.keycloak.events] (executor-thread-1) operationType="CREATE", realmId="a", realmName="master", resourceType="IDENTITY_PROVIDER"',
    '2026-11-02 12:17:27,272 WARN  [org.keycloak.events] (executor-thread-1) type="JWT_AUTHORIZATION_GRANT_ERROR", realmId="b", realmName="idjag-receiver-lab", clientId="receiver-client", userId="null", error="invalid_request", identity_provider_user_id="synthetic-external-user", reason="Token reuse detected", identity_provider="custom-idjag-issuer", ipAddress="172.17.0.1", token_id="trrtag:25fac618"',
    '2026-11-02 12:17:27,275 INFO  [org.keycloak.http.access-log] (executor-thread-1) 172.17.0.1 - - [02/Nov/2026:12:17:27 +0000] "POST /realms/idjag-receiver-lab/protocol/openid-connect/token HTTP/1.1" 400 71',
  ].join('\n');
  const groups = parseKeycloakLog(log, 'idjag-receiver-lab');
  assert.equal(groups.length, 1);
  assert.equal(groups[0].access.status, 400);
  assert.equal(groups[0].events[0].fields.reason, 'Token reuse detected');
  const recorder = createRecorder();
  recorder.reset();
  recorder.origin('http://127.0.0.1:18080', 'keycloak');
  recorder.http({ method: 'POST', url: 'http://127.0.0.1:18080/realms/idjag-receiver-lab/protocol/openid-connect/token', form: { grant_type: 'x' }, status: 400, body: { error: 'invalid_grant', error_description: 'Token reuse detected' } });
  const [entry] = recorder.finalize({ keycloakLog: log, realm: 'idjag-receiver-lab' }).entries;
  assert.equal(entry.keycloak.events[0].type, 'JWT_AUTHORIZATION_GRANT_ERROR');
  assert.equal(entry.keycloak.events[0].reason, 'Token reuse detected');
  assert.equal(entry.keycloak.events[0].idp_user, 'synthetic-external-user');
  assert(!JSON.stringify(entry).includes('172.17.0.1') && !JSON.stringify(entry).includes('trrtag'));
});

test('Keycloak view renders every check as publishable ASCII text', () => {
  const recorder = createRecorder();
  recorder.reset();
  recorder.origin('http://127.0.0.1:18080', 'keycloak');
  const names = Object.values(KEYCLOAK_CHECKS).flatMap(([, checks]) => checks.map(([name]) => name));
  for (const name of names) {
    if (name === 'idjag_receiver_accepts_valid_assertion') {
      const index = recorder.http({
        method: 'POST', url: 'http://127.0.0.1:18080/realms/idjag-receiver-lab/protocol/openid-connect/token',
        form: { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: idjag(), client_secret: 's' }, status: 200,
        body: { access_token: fakeJwt({ alg: 'RS256', typ: 'JWT' }, { iss: 'x', sub: 'y', aud: 'z', iat: NOW, exp: NOW + 120 }), expires_in: 120 },
      });
      recorder.name(index, name);
    } else {
      recorder.local({ name, outcome: 'ok', detail: 'observed locally' });
    }
  }
  const trace = recorder.finalize();
  const lines = renderKeycloakView({
    trace, tests: names.map((name) => ({ name, passed: true })), runtime: { keycloak: '26.8.1', image_digest: `sha256:${'a'.repeat(64)}` },
    cleanup: { container_id: 'b'.repeat(64) },
  });
  assertPublishableLines(lines);
  assert(lines.some((line) => line.includes('-> HTTP 200')));
  assert.match(lines.at(-1), /^Verified current run: 44 \/ 44 checks matched their expected results\.$/);
  assert.throws(() => assertPublishableLines(['token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln']), /SensitiveTraceLine/);
  assert.throws(() => assertPublishableLines(['non ascii \u00e9']), /NonAsciiTraceLine/);
});

test('Keycloak view shows a differing response description and the ID-JAG / access token lifetimes', () => {
  const recorder = createRecorder();
  recorder.reset();
  recorder.origin('http://127.0.0.1:18080', 'keycloak');
  const tokenUrl = 'http://127.0.0.1:18080/realms/idjag-receiver-lab/protocol/openid-connect/token';
  const accessToken = (exp) => fakeJwt({ alg: 'RS256', typ: 'JWT' }, { iss: 'x', sub: 'y', aud: 'z', iat: NOW, exp });
  const post = (name, form, status, body) => recorder.name(recorder.http({ method: 'POST', url: tokenUrl, form, status, body }), name);
  const grantForm = (assertion) => ({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion, client_secret: 's' });
  post('idjag_receiver_accepts_valid_assertion', grantForm(idjag()), 200, { access_token: accessToken(NOW + 120), expires_in: 120 });
  post('invalid_client_credentials_rejected', grantForm(idjag()), 401, { error: 'unauthorized_client', error_description: 'Invalid client or Invalid client credentials' });
  post('idjag_long_exp_with_iat_is_accepted_not_a_lifetime_cap', grantForm(idjag({ exp: NOW + 600 })), 200, { access_token: accessToken(NOW + 120), expires_in: 120 });
  const log = [
    '2026-11-02 12:17:25,010 INFO  [org.keycloak.http.access-log] (executor-thread-1) 172.17.0.1 - - [02/Nov/2026:12:17:25 +0000] "POST /realms/idjag-receiver-lab/protocol/openid-connect/token HTTP/1.1" 200 900',
    '2026-11-02 12:17:26,020 WARN  [org.keycloak.events] (executor-thread-1) type="JWT_AUTHORIZATION_GRANT_ERROR", realmId="b", realmName="idjag-receiver-lab", clientId="receiver-client", error="invalid_client_credentials", ipAddress="172.17.0.1"',
    '2026-11-02 12:17:26,025 INFO  [org.keycloak.http.access-log] (executor-thread-1) 172.17.0.1 - - [02/Nov/2026:12:17:26 +0000] "POST /realms/idjag-receiver-lab/protocol/openid-connect/token HTTP/1.1" 401 70',
    '2026-11-02 12:17:27,030 INFO  [org.keycloak.http.access-log] (executor-thread-1) 172.17.0.1 - - [02/Nov/2026:12:17:27 +0000] "POST /realms/idjag-receiver-lab/protocol/openid-connect/token HTTP/1.1" 200 900',
  ].join('\n');
  const names = Object.values(KEYCLOAK_CHECKS).flatMap(([, checks]) => checks.map(([name]) => name));
  for (const name of names) {
    if (!recorder.entries.some((entry) => entry.name === name)) recorder.local({ name, outcome: 'ok', detail: 'observed locally' });
  }
  const lines = renderKeycloakView({
    trace: recorder.finalize({ keycloakLog: log, realm: 'idjag-receiver-lab' }), tests: names.map((name) => ({ name, passed: true })),
    runtime: { keycloak: '26.8.1', image_digest: `sha256:${'a'.repeat(64)}` }, cleanup: { container_id: 'b'.repeat(64) },
  });
  assertPublishableLines(lines);
  assert(lines.includes('      response error_description="Invalid client or Invalid client credentials"'));
  assert(lines.some((line) => /^ {6}ID-JAG token exp=\d\d:\d\d:\d\dZ \(iat\+600s\); access token exp=\d\d:\d\d:\d\dZ \(iat\+120s\)$/.test(line)));
});

const JWT_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const resign = (jwt, letter) => `${jwt.split('.').slice(0, 2).join('.')}.${letter.repeat(86)}`;
const opaqueKid = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg';

function fillLocals(recorder, sections) {
  const names = Object.values(sections).flatMap(([, checks]) => checks.map(([name]) => name));
  for (const name of names) {
    if (!recorder.entries.some((entry) => entry.name === name)) recorder.local({ name, outcome: 'ok', detail: 'observed locally' });
  }
  return names;
}

test('Keycloak view shows each rejected token with the changed claims, the valid values and the required Bearer claims', () => {
  const recorder = createRecorder();
  recorder.reset();
  recorder.origin('http://127.0.0.1:18080', 'keycloak');
  recorder.origin('http://127.0.0.1:20000', 'resource');
  const realm = 'http://127.0.0.1:18080/realms/idjag-receiver-lab';
  const valid = idjag();
  const access = fakeJwt({ alg: 'RS256', typ: 'JWT', kid: opaqueKid }, {
    iss: realm, sub: 'y', aud: 'lab-api', azp: 'receiver-client', scope: 'lab.read', iat: NOW, exp: NOW + 120,
  });
  const form = (assertion, extra = {}) => ({
    grant_type: JWT_GRANT, assertion, client_id: 'receiver-client', client_secret: 's', scope: 'lab.read', ...extra,
  });
  const post = (name, body, status, response, note) => {
    const index = recorder.http({ method: 'POST', url: `${realm}/protocol/openid-connect/token`, form: body, status, body: response });
    recorder.name(index, name);
    if (note) recorder.note(index, note);
  };
  post('idjag_receiver_accepts_valid_assertion', form(valid), 200, { access_token: access, expires_in: 120 });
  post('idjag_replay_rejected', form(valid), 400, { error: 'invalid_grant' });
  post('idjag_client_binding_rejected', form(idjag({ client_id: 'another-client' })), 400, { error: 'invalid_grant' });
  const withoutJti = JSON.parse(Buffer.from(valid.split('.')[1], 'base64url'));
  delete withoutJti.jti;
  post('idjag_missing_jti_rejected', form(fakeJwt({ alg: 'RS256', typ: 'oauth-id-jag+jwt', kid: 'ephemeral-lab-key' }, withoutJti)), 400, { error: 'invalid_grant' });
  post('idjag_untrusted_signing_key_rejected', form(resign(valid, 'T')), 400, { error: 'invalid_grant' }, 'the assertion is signed with another RSA key');
  post('idjag_expired_rejected', form(idjag({ exp: NOW - 60, iat: NOW - 120 })), 400, { error: 'invalid_grant' });
  post('client_grant_disabled_rejected', form(idjag({ client_id: 'grant-disabled-client' }), { client_id: 'grant-disabled-client' }), 400, { error: 'unauthorized_client' });
  const resource = (name, bearer, status, reason) => {
    const index = recorder.http({
      method: 'GET', url: 'http://127.0.0.1:20000/resource', bearer, status, body: status === 200 ? { result: 'ok' } : { error: 'invalid_token' },
    });
    recorder.name(index, name);
    recorder.server({ source: 'resource', method: 'GET', path: '/resource', status, outcome: status === 200 ? 'accepted' : 'rejected', reason, bearer });
  };
  resource('resource_accepts_receiver_access_token', access, 200, 'Bearer token verified (signature, iss, aud, exp, scope, azp, sub)');
  resource('resource_rejects_identity_assertion_as_bearer', valid, 401, 'Bearer token rejected (UnknownSigningKey)');
  resource('short_lived_access_token_rejected_after_expiry', fakeJwt({ alg: 'RS256', typ: 'JWT', kid: opaqueKid }, {
    iss: realm, sub: 'y', aud: 'lab-api', azp: 'receiver-client', scope: 'lab.read', iat: NOW - 8, exp: NOW - 2,
  }), 401, 'Bearer token rejected (ExpiredJwt)');
  recorder.local({
    name: 'resource_audience_validation_rejects_another_api', outcome: 'rejected', token: recorder.token(access, 'access'),
    detail: 'required aud=another-api, but the token has aud=lab-api: WrongAudience',
  });
  const names = fillLocals(recorder, KEYCLOAK_CHECKS);
  const lines = renderKeycloakView({
    trace: recorder.finalize(), tests: names.map((name) => ({ name, passed: true })),
    runtime: { keycloak: '26.8.1', image_digest: `sha256:${'a'.repeat(64)}` }, cleanup: { container_id: 'b'.repeat(64) },
  });
  assertPublishableLines(lines);
  const text = lines.join('\n');
  assert.match(text, / {6}header {2}typ=oauth-id-jag\+jwt {2}alg=RS256 {2}kid=ephemeral-lab-key {2}sha256:[0-9a-f]{8}/);
  assert.match(text, /assertion: same JWT as the assertion of 01 \(sha256:[0-9a-f]{8}, sent \d\d:\d\d:\d\dZ\)/);
  assert.match(text, /assertion: same header and claims as the assertion of 01 \(a new token, sha256:[0-9a-f]{8}, sent/);
  assert.match(text, /assertion: JWT sha256:[0-9a-f]{8}, sent \d\d:\d\d:\d\dZ; same as the assertion of 01 except\n {17}client_id=another-client \[valid: receiver-client\]/);
  assert(text.includes('sent: the assertion is signed with another RSA key'));
  assert(text.includes('client_id=another-client [valid: receiver-client]'));
  assert(text.includes('jti=(removed) [valid: [REDACTED]]'));
  assert.match(text, /exp=\d\d:\d\d:\d\dZ \(now-60s\) \[valid: now\+120s\]/);
  assert.match(text, /iat=\d\d:\d\d:\d\dZ \(now-120s\) \[valid: now\]/);
  assert(text.includes('sent: client_id=grant-disabled-client [valid: receiver-client]'));
  assert(!text.includes(opaqueKid) && !text.includes(`kid=${opaqueKid}`));
  assert.match(text, /Authorization: Bearer <JWT \d+ chars, sent \d\d:\d\d:\d\dZ, same JWT as the access token returned by 01>/);
  assert.match(text, /Authorization: Bearer <JWT \d+ chars, sent \d\d:\d\d:\d\dZ, same JWT as the assertion of 01>/);
  assert(text.includes(`iss=http://127.0.0.1:18080/custom-issuer [required: ${realm}]`));
  assert(text.includes(`aud=${realm} [required: lab-api]`));
  assert(text.includes('azp=(none) [required: receiver-client]'));
  assert.match(text, /exp=\d\d:\d\d:\d\dZ \(iat\+6s\) \[required: after \d\d:\d\d:\d\dZ \(now\)\]/);
  assert(text.includes('-> rejected: Bearer token rejected (UnknownSigningKey: no key with this kid in the realm JWKS)'));
  assert(text.includes('-> rejected: Bearer token rejected (ExpiredJwt: exp is in the past)'));
  assert.match(text, /access token: same JWT as the access token returned by 01/);
  assert(text.includes('required aud=another-api, but the token has aud=lab-api: WrongAudience'));
});

test('Federated view prints the Entra token once, then fingerprints, differences and the Bearer claims the MCP server requires', () => {
  const user = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  const app = '66666666-7777-8888-9999-000000000000';
  const cli = '99999999-8888-7777-6666-555555555555';
  const recorder = createRecorder();
  recorder.reset();
  for (const [id, alias] of [[TENANT, '[TENANT_ID]'], [user, '[USER_A]'], [app, '[AI_AGENT_APP]'], [cli, '[FRONTEND_CLI]']]) recorder.mask(id, alias);
  const issuerBase = 'http://127.0.0.1:20001';
  const mcpBase = 'http://127.0.0.1:20002';
  const realm = 'http://127.0.0.1:18080/realms/idjag-receiver-lab';
  recorder.origin('http://127.0.0.1:18080', 'keycloak');
  recorder.origin(issuerBase, 'issuer');
  recorder.origin(mcpBase, 'mcp');
  const entra = fakeJwt({ alg: 'RS256', typ: 'JWT', kid: opaqueKid }, {
    iss: `https://login.microsoftonline.com/${TENANT}/v2.0`, aud: app, azp: cli, scp: 'access_as_user', ver: '2.0',
    iat: NOW, nbf: NOW, exp: NOW + 3600, tid: TENANT, oid: user, sub: 'opaque-subject',
  });
  const brokerToken = fakeJwt({ alg: 'RS256', typ: 'oauth-id-jag+jwt', kid: 'ephemeral-lab-key' }, {
    iss: issuerBase, sub: 'mapped-subject', aud: realm, client_id: 'mcp-ema-client', resource: `${mcpBase}/mcp`,
    scope: 'mcp.read', iat: NOW, exp: NOW + 120, jti: 'x',
  });
  const access = fakeJwt({ alg: 'RS256', typ: 'JWT', kid: opaqueKid }, {
    iss: realm, sub: 'y', aud: `${mcpBase}/mcp`, azp: 'mcp-ema-client', scope: 'mcp.read', iat: NOW, exp: NOW + 120,
  });
  const entraSummary = recorder.token(entra, 'entra');
  recorder.local({ name: 'real_entra_user_signature_issuer_audience_expiry_scope_verified', outcome: 'ok', token: entraSummary, detail: 'verified in memory' });
  recorder.local({
    name: 'real_entra_token_wrong_api_audience_rejected', outcome: 'rejected', token: entraSummary,
    detail: `required aud=${app}1, but the token has aud=${app}: WrongAudience`,
  });
  const exchange = (extra, status, body, name, note) => {
    const index = recorder.http({
      method: 'POST', url: `${issuerBase}/token`, status, body, form: {
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: entra, audience: realm,
        resource: `${mcpBase}/mcp`, scope: 'mcp.read', client_id: 'mcp-ema-client', client_secret: 's', ...extra,
      },
    });
    recorder.name(index, name);
    if (note) recorder.note(index, note);
  };
  exchange({ audience: `${realm}/wrong` }, 400, { error: 'invalid_target' }, 'broker_rejects_unregistered_target_audience');
  exchange({ subject_token: 'not-a-token' }, 400, { error: 'invalid_grant' }, 'broker_rejects_invalid_subject_token');
  exchange({}, 200, { access_token: brokerToken, token_type: 'N_A' }, 'custom_broker_issues_and_client_verifies_real_entra_backed_idjag');
  exchange({}, 400, { error: 'invalid_grant' }, 'custom_broker_one_use_bootstrap_replay_policy');
  recorder.name(recorder.http({
    method: 'POST', url: `${realm}/protocol/openid-connect/token`, status: 200, body: { access_token: access },
    form: { grant_type: JWT_GRANT, assertion: brokerToken, client_id: 'mcp-ema-client', client_secret: 's', scope: 'mcp.read', resource: `${mcpBase}/mcp` },
  }), 'native_keycloak_accepts_idjag_and_issues_exact_mcp_audience_token');
  const mcp = (name, bearer, status, reason, headers, note) => {
    const index = recorder.http({
      method: 'POST', url: `${mcpBase}/mcp`, json: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }, bearer, headers, status,
      body: { error: 'invalid_token' },
    });
    recorder.name(index, name);
    if (note) recorder.note(index, note);
    recorder.server({ source: 'mcp', method: 'POST', path: '/mcp', status, outcome: 'rejected', reason, rpc: 'tools/list', bearer });
  };
  mcp('mcp_rejects_original_entra_token_as_resource_bearer', entra, 401, 'Bearer token rejected (UnknownSigningKey)');
  mcp('mcp_rejects_idjag_as_resource_bearer', brokerToken, 401, 'Bearer token rejected (UnknownSigningKey)');
  mcp('mcp_rejects_tampered_access_token', resign(access, 'T'), 401, 'Bearer token rejected (InvalidJwtSignature)', undefined,
    'the first character of the access token signature was changed; header and claims are untouched');
  mcp('mcp_rejects_hostile_origin', access, 403, 'Host or Origin is not the MCP server origin', { Origin: 'https://untrusted.invalid' });
  mcp('mcp_initialize_negotiates_pinned_protocol_and_tools', access, 200, 'session created', { 'MCP-Protocol-Version': '2025-11-25' });
  mcp('mcp_rejects_unsupported_protocol_header', access, 400, 'MCP-Protocol-Version header is missing or unsupported', { 'MCP-Protocol-Version': '2099-01-01' });
  const names = fillLocals(recorder, FEDERATED_CHECKS);
  const lines = renderFederatedView({
    trace: recorder.finalize(), tests: names.map((name) => ({ name, passed: true })),
    runtime: { keycloak: '26.8.1', image_digest: `sha256:${'a'.repeat(64)}` }, cleanup: { container_id: 'b'.repeat(64) },
  });
  assertPublishableLines(lines);
  const text = lines.join('\n').replace(/\n {8,}/g, ' ');
  assert.match(text, /Entra access token: header {2}typ=JWT {2}alg=RS256 {2}kid=\[REDACTED\] {2}sha256:[0-9a-f]{8}/);
  assert(text.includes('Entra access token: same JWT as the Entra access token of 01'));
  assert(text.includes('required aud=[AI_AGENT_APP]1, but the token has aud=[AI_AGENT_APP]: WrongAudience'));
  assert.match(text, /subject_token: same JWT as the Entra access token of 01 \(sha256:[0-9a-f]{8}, sent/);
  assert(text.includes(`sent: audience=${realm}/wrong [valid: ${realm}]`));
  assert.match(text, /sent: subject_token=not-a-token \[valid: <JWT \d+ chars>\]/);
  assert.match(text, /ID-JAG token returned: header {2}typ=oauth-id-jag\+jwt {2}alg=RS256 {2}kid=ephemeral-lab-key/);
  assert.match(text, /assertion: same JWT as the ID-JAG token returned by 1\d \(sha256:/);
  assert.match(text, /access token returned: header {2}typ=JWT {2}alg=RS256 {2}kid=\[REDACTED\]/);
  assert(text.includes(`iss=https://login.microsoftonline.com/[TENANT_ID]/v2.0 [required: ${realm}]`));
  assert(text.includes(`aud=[AI_AGENT_APP] [required: ${mcpBase}/mcp]`));
  assert(text.includes('scope=(none) [required: mcp.read]'));
  assert(text.includes(`iss=${issuerBase} [required: ${realm}]`));
  assert.match(text, /same claims as the access token returned by 1\d; a different JWT/);
  assert(text.includes('sent: the first character of the access token signature was changed; header and claims are untouched'));
  assert(text.includes('sent header origin: https://untrusted.invalid'));
  assert(text.includes('sent header mcp-protocol-version: 2099-01-01'));
  assert(!text.includes('sent header mcp-protocol-version: 2025-11-25'));
});
