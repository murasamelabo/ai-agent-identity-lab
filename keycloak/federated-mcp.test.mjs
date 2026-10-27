import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import {
  inspectKeycloakPair, renderKeycloakTokenView, verifySignedJwt,
} from './federated-mcp.mjs';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ISSUER = 'http://127.0.0.1/synthetic-test-issuer';
const AUDIENCE = 'synthetic-test-resource';
const jwks = { keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'test-key', use: 'sig' }] };
const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
function token(claims = {}, header = {}) {
  const now = Math.floor(Date.now() / 1000);
  const data = `${encode({ alg: 'RS256', kid: 'test-key', ...header })}.${encode({
    iss: ISSUER, aud: AUDIENCE, iat: now, exp: now + 120, ...claims,
  })}`;
  return `${data}.${sign('RSA-SHA256', Buffer.from(data), privateKey).toString('base64url')}`;
}

test('signed JWT verifier accepts the exact trusted signature, issuer, audience and time', () => {
  assert.equal(verifySignedJwt(token(), jwks, ISSUER, AUDIENCE).claims.aud, AUDIENCE);
});

test('signed JWT verifier rejects different issuer, audience and multiple audiences', () => {
  assert.throws(() => verifySignedJwt(token(), jwks, `${ISSUER}/wrong`, AUDIENCE), /WrongIssuer/);
  assert.throws(() => verifySignedJwt(token(), jwks, ISSUER, 'wrong-resource'), /WrongAudience/);
  assert.throws(() => verifySignedJwt(token({ aud: [AUDIENCE, 'another-resource'] }), jwks, ISSUER, AUDIENCE), /WrongAudience/);
});

test('signed JWT verifier rejects a modified payload and unexpected algorithm', () => {
  const parts = token().split('.');
  parts[1] = encode({ iss: ISSUER, aud: AUDIENCE, scope: 'admin' });
  assert.throws(() => verifySignedJwt(parts.join('.'), jwks, ISSUER, AUDIENCE), /InvalidJwtSignature/);
  assert.throws(() => verifySignedJwt(token({}, { alg: 'none' }), jwks, ISSUER, AUDIENCE), /InvalidJwtAlgorithm/);
});

test('signed JWT verifier rejects expired, future-issued and not-yet-valid tokens', () => {
  const now = Math.floor(Date.now() / 1000);
  assert.throws(() => verifySignedJwt(token({ exp: now - 1 }), jwks, ISSUER, AUDIENCE), /ExpiredJwt/);
  assert.throws(() => verifySignedJwt(token({ iat: now + 60 }), jwks, ISSUER, AUDIENCE), /InvalidIssuedAt/);
  assert.throws(() => verifySignedJwt(token({ nbf: now + 60 }), jwks, ISSUER, AUDIENCE), /JwtNotYetValid/);
});

test('Keycloak token pair inspector redacts identifiers and renders ID-JAG vs Access Token views', () => {
  const idjag = token({
    sub: 'synthetic-external-user',
    aud: 'http://127.0.0.1:18080/realms/idjag-receiver-lab',
    client_id: 'receiver-client',
    resource: 'lab-api',
    scope: 'lab.read',
    jti: 'secret-jti-1',
  }, { typ: 'oauth-id-jag+jwt' });
  const access = token({
    iss: 'http://127.0.0.1:18080/realms/idjag-receiver-lab',
    sub: '00000000-0000-0000-0000-000000000001',
    aud: ['lab-api', 'account'],
    azp: 'receiver-client',
    typ: 'Bearer',
    scope: 'lab.read profile email',
    jti: 'secret-jti-2',
  }, { typ: 'JWT' });
  const inspection = inspectKeycloakPair(idjag, access);
  assert.equal(inspection.idjag.header.typ, 'oauth-id-jag+jwt');
  assert.equal(inspection.idjag.header.kid, '[REDACTED]');
  assert.equal(inspection.idjag.payload.jti, '[REDACTED]');
  assert.equal(inspection.idjag.payload.aud, 'http://127.0.0.1:18080/realms/idjag-receiver-lab');
  assert.equal(inspection.idjag.payload.client_id, 'receiver-client');
  assert.equal(inspection.idjag.payload.resource, 'lab-api');
  assert.equal(inspection.keycloak_access_token.header.typ, 'JWT');
  assert.equal(inspection.keycloak_access_token.payload.sub, '[LINKED_LOCAL_USER]');
  assert.deepEqual(inspection.keycloak_access_token.payload.aud, ['lab-api', 'account']);
  assert.equal(inspection.keycloak_access_token.payload.azp, 'receiver-client');
  const report = { passed: true, token_inspection: inspection };
  const idjagOut = renderKeycloakTokenView(report, 'idjag', 'payload');
  const atOut = renderKeycloakTokenView(report, 'keycloak_access_token', 'payload');
  assert.match(idjagOut, /header\.typ=oauth-id-jag\+jwt/);
  assert.match(idjagOut, /Header:\n\{\n  "alg": "RS256",\n  "typ": "oauth-id-jag\+jwt",\n  "kid": "\[REDACTED\]"\n\}\nPayload:/);
  assert.match(idjagOut, /HTTP 401 invalid_token/);
  assert.match(atOut, /header\.typ=JWT/);
  assert.match(atOut, /Header:\n\{\n  "alg": "RS256",\n  "typ": "JWT",\n  "kid": "\[REDACTED\]"\n\}\nPayload:/);
  assert.match(atOut, /HTTP 200/);
  assert(!idjagOut.includes('secret-jti-1'));
  assert(!atOut.includes('00000000-0000-0000-0000-000000000001'));
});
