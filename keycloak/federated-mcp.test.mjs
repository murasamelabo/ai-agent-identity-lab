import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { verifySignedJwt } from './federated-mcp.mjs';

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
