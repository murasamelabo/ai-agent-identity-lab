import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  createHash, createPublicKey, randomBytes, randomUUID, sign, timingSafeEqual, verify,
} from 'node:crypto';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';

const VERSION = '2025-11-25';
const EMA_REVISION = 'e5eef546e4fc025ceaee6a935aa33cb4cd904b4f';
const ACCESS = 'urn:ietf:params:oauth:token-type:access_token';
const IDJAG = 'urn:ietf:params:oauth:token-type:id-jag';
const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const JWT_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const CLI_CLIENT = '04b07795-8ddb-461a-bbee-02f9e1bf7b46';
const GUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
const MAX_BODY = 65536;

function requireValue(condition, code) {
  if (!condition) throw new Error(code);
}

function readPrivateContract() {
  try {
    requireValue(process.platform === 'win32' && process.env.LOCALAPPDATA, 'PrivateStateUnavailable');
    const root = join(process.env.LOCALAPPDATA, 'Shoten21IdentityLab');
    requireValue(!root.toLowerCase().includes('onedrive') && !lstatSync(root).isSymbolicLink(), 'PrivateStateUnavailable');
    const readJson = (path) => JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
    const run = existsSync(join(root, 'latest.json'))
      ? readJson(join(root, 'latest.json')).run
      : readFileSync(join(root, 'latest.txt'), 'utf8').replace(/^\uFEFF/, '').trim();
    requireValue(typeof run === 'string' && /^[a-f0-9]{32}$/.test(run), 'PrivateStateUnavailable');
    const directory = join(root, run);
    const path = join(directory, 'state.json');
    requireValue(!lstatSync(directory).isSymbolicLink() && !lstatSync(path).isSymbolicLink(), 'PrivateStateUnavailable');
    const state = readJson(path);
    const contract = {
      tenant: state.tenant, user: state.user,
      apiA: state.apps?.a?.appId, apiB: state.apps?.b?.appId,
    };
    requireValue(!state.cleanup_completed_at && Object.values(contract).every((v) => typeof v === 'string' && GUID.test(v)), 'PrivateStateUnavailable');
    return contract;
  } catch {
    throw new Error('EntraPrivateStateUnavailable');
  }
}

function acquireOwnApiUserToken(contract) {
  try {
    // All interpolated fields were restricted to GUIDs; no token is a command argument.
    const command = `az account get-access-token --tenant ${contract.tenant} --scope api://${contract.apiA}/access_as_user --only-show-errors --output json`;
    const output = execFileSync(process.env.ComSpec ?? 'C:\\Windows\\System32\\cmd.exe', [
      '/d', '/s', '/c', command,
    ], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true, timeout: 120000, maxBuffer: 4 * 1024 * 1024,
    });
    const token = JSON.parse(output).accessToken;
    requireValue(typeof token === 'string' && token.length > 0, 'EntraSilentTokenUnavailable');
    return token;
  } catch {
    // Do not print subprocess stdout/stderr, command arguments, identifiers, or paths.
    throw new Error('EntraSilentTokenUnavailable');
  }
}

async function http(url, { method = 'GET', json, form, bearer, headers = {} } = {}) {
  const sentHeaders = { ...headers };
  if (bearer) sentHeaders.authorization = `Bearer ${bearer}`;
  let body;
  if (json !== undefined) {
    sentHeaders['content-type'] = 'application/json';
    body = JSON.stringify(json);
  }
  if (form) {
    sentHeaders['content-type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(form).toString();
  }
  const response = await fetch(url, {
    method, headers: sentHeaders, body, redirect: 'error', signal: AbortSignal.timeout(15000),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null, headers: response.headers };
}

export function verifySignedJwt(jwt, jwks, issuer, audience) {
  requireValue(typeof jwt === 'string' && jwt.length <= MAX_BODY, 'InvalidJwt');
  const parts = jwt.split('.');
  requireValue(parts.length === 3, 'InvalidJwt');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  requireValue(header.alg === 'RS256' && typeof header.kid === 'string', 'InvalidJwtAlgorithm');
  const jwk = jwks.keys.find((key) => key.kid === header.kid && key.kty === 'RSA' && (!key.use || key.use === 'sig'));
  requireValue(jwk, 'UnknownSigningKey');
  requireValue(verify(
    'RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`),
    createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(parts[2], 'base64url'),
  ), 'InvalidJwtSignature');
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  const now = Math.floor(Date.now() / 1000);
  requireValue(claims.iss === issuer, 'WrongIssuer');
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  requireValue(audiences.length === 1 && audiences[0] === audience, 'WrongAudience');
  requireValue(Number.isInteger(claims.exp) && claims.exp > now, 'ExpiredJwt');
  requireValue(Number.isInteger(claims.iat) && claims.iat <= now, 'InvalidIssuedAt');
  requireValue(claims.nbf === undefined || (Number.isInteger(claims.nbf) && claims.nbf <= now), 'JwtNotYetValid');
  return { header, claims };
}

export function inspectKeycloakPair(idjagJwt, accessJwt) {
  const split = (jwt) => {
    const parts = String(jwt ?? '').split('.');
    requireValue(parts.length === 3, 'InvalidJwt');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
    const knownPrefix = Buffer.from('{"alg":"RS256",').toString('base64url').slice(0, 16);
    const prefix = parts[0].startsWith(knownPrefix) ? `${knownPrefix}.` : '';
    return {
      compact_redacted: `${prefix}[HEADER_REDACTED].[PAYLOAD_REDACTED].[SIGNATURE_REDACTED]`,
      segment_lengths: {
        header: parts[0].length,
        payload: parts[1].length,
        signature: parts[2].length,
      },
      header,
      claims,
    };
  };
  const j = split(idjagJwt);
  const a = split(accessJwt);
  requireValue(j.header.alg === 'RS256' && j.header.typ === 'oauth-id-jag+jwt', 'InvalidIdJagHeader');
  requireValue(a.header.alg === 'RS256' && a.header.typ === 'JWT', 'InvalidAccessTokenHeader');
  return {
    idjag: {
      role: 'authorization_grant',
      direct_api_bearer_result: 'HTTP 401 invalid_token',
      compact_redacted: j.compact_redacted,
      segment_lengths: j.segment_lengths,
      header: {
        alg: j.header.alg,
        typ: j.header.typ,
        kid: '[REDACTED]',
      },
      payload: {
        iss: j.claims.iss,
        sub: j.claims.sub === 'synthetic-external-user' ? 'synthetic-external-user' : '[MAPPED_ENTRA_USER]',
        aud: j.claims.aud,
        client_id: j.claims.client_id,
        resource: j.claims.resource,
        scope: j.claims.scope,
        jti: '[REDACTED]',
        iat: j.claims.iat,
        exp: j.claims.exp,
      },
    },
    keycloak_access_token: {
      role: 'access_token',
      direct_api_bearer_result: 'HTTP 200',
      compact_redacted: a.compact_redacted,
      segment_lengths: a.segment_lengths,
      header: {
        alg: a.header.alg,
        typ: a.header.typ,
        kid: '[REDACTED]',
      },
      payload: {
        iss: a.claims.iss,
        sub: '[LINKED_LOCAL_USER]',
        aud: a.claims.aud,
        azp: a.claims.azp,
        typ: a.claims.typ,
        scope: a.claims.scope,
        jti: '[REDACTED]',
        iat: a.claims.iat,
        exp: a.claims.exp,
      },
    },
  };
}

export function renderKeycloakTokenView(report, name, view) {
  requireValue(report?.passed === true, 'InvalidKeycloakReport');
  requireValue(['idjag', 'keycloak_access_token'].includes(name), 'InvalidTokenName');
  requireValue(['encoded', 'header', 'payload'].includes(view), 'InvalidTokenView');
  const entry = report?.token_inspection?.[name];
  requireValue(entry && typeof entry === 'object', 'MissingTokenInspection');
  requireValue(entry.header?.alg === 'RS256' && entry.header?.kid === '[REDACTED]', 'InvalidHeaderInspection');
  requireValue(
    name === 'idjag'
      ? entry.header.typ === 'oauth-id-jag+jwt' && entry.role === 'authorization_grant' && entry.direct_api_bearer_result === 'HTTP 401 invalid_token'
      : entry.header.typ === 'JWT' && entry.role === 'access_token' && entry.direct_api_bearer_result === 'HTTP 200',
    'InvalidRoleOrTypeInspection',
  );
  const lines = [
    `VERIFIED KEYCLOAK LAB JWT - ${view.toUpperCase()} (publication-redacted)`,
    `Token: ${name} (role=${entry.role}; header.typ=${entry.header.typ})`,
    'Saved sanitized evidence; no token is acquired by this view.',
    'Source verified: RS256 signature, issuer, audience, lifetime.',
    `Direct API Bearer check (GET /resource): ${entry.direct_api_bearer_result}`,
    '',
  ];
  if (view === 'encoded') {
    const lengths = entry.segment_lengths;
    lines.push(
      entry.compact_redacted,
      '',
      `Base64url lengths (characters): header=${lengths.header}; payload=${lengths.payload}; signature=${lengths.signature}`,
      'Original header prefix only; all remaining JWT content is redacted.',
      'This redacted text is not a usable or verifiable JWT.',
    );
  } else if (view === 'payload') {
    lines.push(
      'Header:',
      JSON.stringify(entry.header, null, 2),
      'Payload:',
      JSON.stringify(entry.payload, null, 2),
      '',
      'Selected original fields only; identity values are redacted.',
      'Omitted fields are not evidence of absence in the original JWT.',
      'Decoding alone is not signature validation.',
    );
  } else {
    lines.push(
      JSON.stringify(entry[view], null, 2),
      '',
      'Selected original fields only; identity values are redacted.',
      'Omitted fields are not evidence of absence in the original JWT.',
      'Decoding alone is not signature validation.',
    );
  }
  return lines.join('\n');
}

function safeEqual(actual, expected) {
  const a = Buffer.from(actual ?? '');
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function respond(res, status, body, headers = {}) {
  res.writeHead(status, {
    'cache-control': 'no-store', pragma: 'no-cache',
    ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers,
  });
  res.end(body === undefined ? undefined : JSON.stringify(body));
}

async function body(req) {
  const parts = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    requireValue(size <= MAX_BODY, 'RequestTooLarge');
    parts.push(chunk);
  }
  return Buffer.concat(parts).toString('utf8');
}

async function listen(server) {
  server.requestTimeout = 10000;
  server.headersTimeout = 10000;
  await new Promise((resolve, reject) => {
    server.once('error', () => reject(new Error('LoopbackServerUnavailable')));
    server.listen(0, '127.0.0.1', resolve);
  });
  return `http://127.0.0.1:${server.address().port}`;
}

export async function prepareFederatedMcp({ receiverIssuer, privateKey, publicKey }) {
  const contract = readPrivateContract();
  const token = acquireOwnApiUserToken(contract); // One authorized acquisition; no retry/login fallback.
  const issuer = `https://login.microsoftonline.com/${contract.tenant}/v2.0`;
  let jwks;
  try {
    const metadata = await http(`${issuer}/.well-known/openid-configuration`);
    requireValue(metadata.status === 200 && metadata.body.issuer === issuer, 'EntraMetadataUnavailable');
    const keysUrl = new URL(metadata.body.jwks_uri);
    requireValue(keysUrl.protocol === 'https:' && keysUrl.hostname === 'login.microsoftonline.com', 'UntrustedEntraKeysEndpoint');
    const keys = await http(keysUrl.href);
    requireValue(keys.status === 200 && Array.isArray(keys.body.keys), 'EntraKeysUnavailable');
    jwks = keys.body;
  } catch {
    throw new Error('EntraMetadataOrKeysUnavailable');
  }
  const validate = (input, { audience = contract.apiA, scope = 'access_as_user' } = {}) => {
    const { claims } = verifySignedJwt(input, jwks, issuer, audience);
    requireValue(claims.ver === '2.0' && claims.tid === contract.tenant, 'WrongEntraTenantOrVersion');
    requireValue(claims.oid === contract.user && typeof claims.sub === 'string', 'WrongEntraUser');
    requireValue(claims.azp === CLI_CLIENT, 'WrongEntraAuthorizedClient');
    requireValue(typeof claims.scp === 'string' && claims.scp.split(' ').includes(scope), 'MissingEntraUserScope');
    return claims;
  };
  let claims;
  try { claims = validate(token); } catch { throw new Error('EntraUserTokenValidationFailed'); }
  return new FederatedMcp({
    token, claims, validate, wrongAudience: contract.apiB,
    receiverIssuer, privateKey, publicKey,
  });
}

class FederatedMcp {
  constructor(options) {
    Object.assign(this, options);
    this.clientId = 'mcp-ema-client';
    this.receiverSecret = randomBytes(32).toString('base64url');
    this.brokerSecret = randomBytes(32).toString('base64url');
    this.subject = createHash('sha256').update(`${this.claims.iss}\0${this.claims.sub}`).digest('base64url');
    this.sessions = new Map();
    this.usedInputTokens = new Set();
    this.tests = [];
  }

  async start() {
    this.brokerServer = createServer((req, res) => {
      this.brokerRequest(req, res).catch(() => {
        if (!res.headersSent) respond(res, 400, { error: 'invalid_request' });
        else res.end();
      });
    });
    this.issuer = await listen(this.brokerServer);
    this.mcpServer = createServer((req, res) => {
      this.mcpRequest(req, res).catch(() => {
        if (!res.headersSent) respond(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid request' } });
        else res.end();
      });
    });
    this.mcpBase = await listen(this.mcpServer);
    this.resource = `${this.mcpBase}/mcp`;
    this.metadataUrl = `${this.mcpBase}/.well-known/oauth-protected-resource/mcp`;
  }

  checkOrigin(req, base) {
    return req.headers.host === new URL(base).host && (!req.headers.origin || req.headers.origin === base);
  }

  issueAssertion() {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: this.issuer, sub: this.subject, aud: this.receiverIssuer,
      client_id: this.clientId, resource: this.resource, scope: 'mcp.read',
      iat: now, exp: now + 120, jti: randomUUID(),
    };
    const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const unsigned = `${encode({ alg: 'RS256', kid: 'ephemeral-lab-key', typ: 'oauth-id-jag+jwt' })}.${encode(payload)}`;
    return `${unsigned}.${sign('RSA-SHA256', Buffer.from(unsigned), this.privateKey).toString('base64url')}`;
  }

  async brokerRequest(req, res) {
    if (!this.checkOrigin(req, this.issuer)) return respond(res, 403, { error: 'invalid_request' });
    if (req.method === 'GET' && req.url === '/.well-known/oauth-authorization-server') {
      return respond(res, 200, {
        issuer: this.issuer, token_endpoint: `${this.issuer}/token`,
        jwks_uri: `${this.issuer}/jwks`, grant_types_supported: [EXCHANGE],
        token_endpoint_auth_methods_supported: ['client_secret_post'],
      });
    }
    if (req.method === 'GET' && req.url === '/jwks') {
      return respond(res, 200, { keys: [{
        ...this.publicKey.export({ format: 'jwk' }), kid: 'ephemeral-lab-key', use: 'sig', alg: 'RS256',
      }] });
    }
    if (req.method !== 'POST' || req.url !== '/token') return respond(res, 404, { error: 'invalid_request' });
    if (!req.headers['content-type']?.startsWith('application/x-www-form-urlencoded')) return respond(res, 415, { error: 'invalid_request' });
    const form = new URLSearchParams(await body(req));
    if ([...new Set(form.keys())].some((name) => form.getAll(name).length !== 1)) return respond(res, 400, { error: 'invalid_request' });
    if (form.get('client_id') !== this.clientId || !safeEqual(form.get('client_secret'), this.brokerSecret)) {
      return respond(res, 401, { error: 'invalid_client' });
    }
    if (form.get('grant_type') !== EXCHANGE) return respond(res, 400, { error: 'unsupported_grant_type' });
    if (form.get('requested_token_type') !== IDJAG || form.get('subject_token_type') !== ACCESS) return respond(res, 400, { error: 'invalid_request' });
    if (form.get('audience') !== this.receiverIssuer || form.get('resource') !== this.resource) return respond(res, 400, { error: 'invalid_target' });
    if (form.get('scope') !== 'mcp.read') return respond(res, 400, { error: 'invalid_scope' });
    const input = form.get('subject_token');
    try { this.validate(input); } catch { return respond(res, 400, { error: 'invalid_grant' }); }
    const tokenHash = createHash('sha256').update(input).digest('hex');
    if (this.usedInputTokens.has(tokenHash)) return respond(res, 400, { error: 'invalid_grant' });
    this.usedInputTokens.add(tokenHash);
    return respond(res, 200, {
      issued_token_type: IDJAG, access_token: this.issueAssertion(),
      token_type: 'N_A', expires_in: 120, scope: 'mcp.read',
    });
  }

  verifyMcpToken(token, { audience = this.resource, scope = 'mcp.read' } = {}) {
    const { claims } = verifySignedJwt(token, this.receiverJwks, this.receiverIssuer, audience);
    requireValue(claims.sub === this.localSubject && claims.azp === this.clientId, 'WrongMcpSubjectOrClient');
    requireValue(typeof claims.scope === 'string' && claims.scope.split(' ').includes(scope), 'MissingMcpScope');
    return claims;
  }

  async mcpRequest(req, res) {
    if (!this.checkOrigin(req, this.mcpBase)) return respond(res, 403, { error: 'invalid_origin' });
    if (req.method === 'GET' && req.url === '/.well-known/oauth-protected-resource/mcp') {
      return respond(res, 200, {
        resource: this.resource, authorization_servers: [this.receiverIssuer],
        scopes_supported: ['mcp.read'], bearer_methods_supported: ['header'],
      });
    }
    if (req.url !== '/mcp') return respond(res, 404);
    try {
      requireValue(req.headers.authorization?.startsWith('Bearer '), 'MissingBearer');
      this.verifyMcpToken(req.headers.authorization.slice(7));
    } catch {
      return respond(res, 401, { error: 'invalid_token' }, {
        'www-authenticate': `Bearer resource_metadata="${this.metadataUrl}", scope="mcp.read"`,
      });
    }
    if (req.method === 'GET') return respond(res, 405, undefined, { allow: 'POST, DELETE' });
    const sessionId = req.headers['mcp-session-id'];
    const session = this.sessions.get(sessionId);
    if (req.method === 'DELETE') {
      if (req.headers['mcp-protocol-version'] !== VERSION) return respond(res, 400);
      if (!session) return respond(res, 404);
      this.sessions.delete(sessionId);
      return respond(res, 204);
    }
    if (req.method !== 'POST') return respond(res, 405, undefined, { allow: 'POST, GET, DELETE' });
    if (!req.headers.accept?.includes('application/json') || !req.headers.accept.includes('text/event-stream')) return respond(res, 406);
    if (!req.headers['content-type']?.startsWith('application/json')) return respond(res, 415);
    let message;
    try { message = JSON.parse(await body(req)); } catch {
      return respond(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    }
    if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string' || Array.isArray(message)
      || (Object.hasOwn(message, 'id') && !['string', 'number'].includes(typeof message.id))) {
      return respond(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    }
    const reply = (result) => respond(res, 200, { jsonrpc: '2.0', id: message.id, result });
    const rpcError = (code, text) => respond(res, 200, { jsonrpc: '2.0', id: message.id, error: { code, message: text } });
    if (message.method === 'initialize') {
      if (sessionId || !Object.hasOwn(message, 'id') || typeof message.params?.protocolVersion !== 'string'
        || !message.params.capabilities || typeof message.params.clientInfo?.name !== 'string'
        || typeof message.params.clientInfo?.version !== 'string') return respond(res, 400);
      if (this.sessions.size >= 8) return respond(res, 429);
      const id = randomUUID();
      this.sessions.set(id, { initialized: false });
      return respond(res, 200, {
        jsonrpc: '2.0', id: message.id, result: {
          protocolVersion: VERSION, capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'shoten-protected-mcp-prototype', version: '1.0.0' },
        },
      }, { 'mcp-session-id': id });
    }
    if (req.headers['mcp-protocol-version'] !== VERSION) return respond(res, 400);
    if (!sessionId) return respond(res, 400);
    if (!session) return respond(res, 404);
    if (message.method === 'notifications/initialized' && !Object.hasOwn(message, 'id')) {
      session.initialized = true;
      return respond(res, 202);
    }
    if (!session.initialized) return respond(res, 400);
    if (!Object.hasOwn(message, 'id')) return respond(res, 202);
    if (message.method === 'ping') return reply({});
    if (message.method === 'tools/list') {
      return reply({ tools: [{
        name: 'read_synthetic_document', description: 'Read a synthetic lab document; never real user data.',
        inputSchema: {
          type: 'object', properties: { documentId: { type: 'string', enum: ['alice', 'bob'] } },
          required: ['documentId'], additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      }] });
    }
    if (message.method === 'tools/call') {
      const args = message.params?.arguments;
      if (message.params?.name !== 'read_synthetic_document' || !args || Array.isArray(args)
        || Object.keys(args).length !== 1 || !['alice', 'bob'].includes(args.documentId)) {
        return rpcError(-32602, 'Invalid tool name or arguments');
      }
      if (args.documentId === 'bob') return reply({
        content: [{ type: 'text', text: 'Access denied to synthetic other-user document.' }], isError: true,
      });
      return reply({
        content: [{ type: 'text', text: 'Synthetic Alice document: Entra-backed MCP authorization succeeded.' }],
        isError: false,
      });
    }
    return rpcError(-32601, 'Method not found');
  }

  async configureReceiver(admin, localSubject) {
    this.localSubject = localSubject;
    const realm = 'idjag-receiver-lab';
    const scope = await admin(`${realm}/client-scopes`, 'POST', {
      name: 'mcp.read', protocol: 'openid-connect', attributes: { 'include.in.token.scope': 'true' },
      protocolMappers: [{
        name: 'exact-mcp-resource-audience', protocol: 'openid-connect', protocolMapper: 'oidc-audience-mapper',
        config: { 'included.custom.audience': this.resource, 'access.token.claim': 'true', 'id.token.claim': 'false' },
      }],
    });
    const scopeId = scope.location.split('/').at(-1);
    await admin(`${realm}/clients`, 'POST', {
      clientId: this.clientId, secret: this.receiverSecret, enabled: true,
      protocol: 'openid-connect', publicClient: false, standardFlowEnabled: false,
      directAccessGrantsEnabled: false, serviceAccountsEnabled: false,
      attributes: {
        'oauth2.jwt.authorization.grant.enabled': 'true',
        'oauth2.jwt.authorization.grant.idp': 'custom-idjag-issuer',
      },
    });
    const clients = await admin(`${realm}/clients?clientId=${this.clientId}`);
    const clientPath = `${realm}/clients/${clients.body[0].id}`;
    const defaults = await admin(`${clientPath}/default-client-scopes`);
    for (const item of defaults.body) {
      if (item.name !== 'basic') await admin(`${clientPath}/default-client-scopes/${item.id}`, 'DELETE');
    }
    await admin(`${clientPath}/optional-client-scopes/${scopeId}`, 'PUT');
    const keys = await http(`${this.receiverIssuer}/protocol/openid-connect/certs`);
    requireValue(keys.status === 200 && Array.isArray(keys.body.keys), 'ReceiverKeysUnavailable');
    this.receiverJwks = keys.body;
  }

  check(name, response, status, error) {
    assert.equal(response.status, status, `${name}: unexpected HTTP status`);
    if (error) assert.equal(response.body?.error, error, `${name}: unexpected error code`);
    this.tests.push({
      name, passed: true, http_status: response.status,
      ...(error ? { oauth_error: error } : {}),
    });
    console.log(`PASS ${name}: HTTP ${status}`);
  }

  async execute() {
    const localCheck = (name, action) => {
      action();
      this.tests.push({ name, passed: true });
      console.log(`PASS ${name}`);
    };
    localCheck('real_entra_user_signature_issuer_audience_expiry_scope_verified', () => this.validate(this.token));
    localCheck('real_entra_token_wrong_api_audience_rejected', () => assert.throws(
      () => this.validate(this.token, { audience: this.wrongAudience }), /WrongAudience/,
    ));
    localCheck('real_entra_token_missing_required_user_scope_rejected', () => assert.throws(
      () => this.validate(this.token, { scope: 'unauthorized.synthetic.scope' }), /MissingEntraUserScope/,
    ));
    const anonymous = await http(this.resource, { method: 'POST', json: { jsonrpc: '2.0', id: 1, method: 'tools/list' } });
    this.check('mcp_missing_token_challenges_with_protected_resource_metadata', anonymous, 401, 'invalid_token');
    assert(anonymous.headers.get('www-authenticate').includes(this.metadataUrl));
    const metadata = await http(this.metadataUrl);
    assert.equal(metadata.body.resource, this.resource);
    assert.deepEqual(metadata.body.authorization_servers, [this.receiverIssuer]);
    this.check('mcp_rfc9728_protected_resource_metadata', metadata, 200);
    const brokerMetadata = await http(`${this.issuer}/.well-known/oauth-authorization-server`);
    assert.equal(brokerMetadata.body.issuer, this.issuer);
    this.check('custom_broker_metadata', brokerMetadata, 200);
    const receiverMetadata = await http(`${this.receiverIssuer}/.well-known/openid-configuration`);
    this.check('native_keycloak_metadata_observed_without_fabricated_idjag_profile', receiverMetadata, 200);
    const advertised = receiverMetadata.body.authorization_grant_profiles_supported ?? [];

    const exchange = (extra = {}) => http(`${this.issuer}/token`, {
      method: 'POST', form: {
        grant_type: EXCHANGE, requested_token_type: IDJAG, subject_token_type: ACCESS,
        subject_token: this.token, audience: this.receiverIssuer, resource: this.resource,
        scope: 'mcp.read', client_id: this.clientId, client_secret: this.brokerSecret, ...extra,
      },
    });
    this.check('broker_rejects_unregistered_target_audience', await exchange({ audience: `${this.receiverIssuer}/wrong` }), 400, 'invalid_target');
    this.check('broker_rejects_unapproved_resource', await exchange({ resource: `${this.resource}/wrong` }), 400, 'invalid_target');
    this.check('broker_rejects_unapproved_scope', await exchange({ scope: 'mcp.admin' }), 400, 'invalid_scope');
    this.check('broker_rejects_wrong_client_secret', await exchange({ client_secret: 'incorrect-synthetic-secret' }), 401, 'invalid_client');
    this.check('broker_rejects_invalid_subject_token', await exchange({ subject_token: 'not-a-token' }), 400, 'invalid_grant');
    const issued = await exchange();
    assert.equal(issued.body.issued_token_type, IDJAG);
    assert.equal(issued.body.token_type, 'N_A');
    const brokerJwks = (await http(`${this.issuer}/jwks`)).body;
    const assertion = issued.body.access_token;
    const brokerJwt = verifySignedJwt(assertion, brokerJwks, this.issuer, this.receiverIssuer);
    assert.equal(brokerJwt.header.typ, 'oauth-id-jag+jwt');
    assert.equal(brokerJwt.claims.client_id, this.clientId);
    assert.equal(brokerJwt.claims.resource, this.resource);
    assert.equal(brokerJwt.claims.scope, 'mcp.read');
    assert.equal(brokerJwt.claims.sub, this.subject);
    assert.equal(typeof brokerJwt.claims.jti, 'string');
    this.check('custom_broker_issues_and_client_verifies_real_entra_backed_idjag', issued, 200);
    this.check('custom_broker_one_use_bootstrap_replay_policy', await exchange(), 400, 'invalid_grant');

    const receiverForm = {
      grant_type: JWT_GRANT, assertion, client_id: this.clientId,
      client_secret: this.receiverSecret, scope: 'mcp.read', resource: this.resource,
    };
    const access = await http(`${this.receiverIssuer}/protocol/openid-connect/token`, { method: 'POST', form: receiverForm });
    const accessToken = access.body.access_token;
    const accessClaims = this.verifyMcpToken(accessToken);
    assert(accessClaims.exp <= brokerJwt.claims.exp);
    this.check('native_keycloak_accepts_idjag_and_issues_exact_mcp_audience_token', access, 200);
    this.check('native_keycloak_rejects_idjag_replay', await http(`${this.receiverIssuer}/protocol/openid-connect/token`, {
      method: 'POST', form: receiverForm,
    }), 400, 'invalid_grant');
    localCheck('real_keycloak_token_wrong_resource_audience_rejected', () => assert.throws(
      () => this.verifyMcpToken(accessToken, { audience: `${this.resource}/wrong` }), /WrongAudience/,
    ));
    localCheck('real_keycloak_token_missing_required_admin_scope_rejected', () => assert.throws(
      () => this.verifyMcpToken(accessToken, { scope: 'mcp.admin' }), /MissingMcpScope/,
    ));

    let sessionId;
    let nextId = 10;
    const rpc = (method, params = {}, options = {}) => http(this.resource, {
      method: 'POST', json: { jsonrpc: '2.0', id: nextId++, method, params },
      bearer: options.bearer ?? accessToken,
      headers: {
        accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': VERSION,
        ...(sessionId ? { 'MCP-Session-Id': sessionId } : {}), ...options.headers,
      },
    });
    this.check('mcp_rejects_original_entra_token_as_resource_bearer', await rpc('tools/list', {}, { bearer: this.token }), 401, 'invalid_token');
    this.check('mcp_rejects_idjag_as_resource_bearer', await rpc('tools/list', {}, { bearer: assertion }), 401, 'invalid_token');
    const segments = accessToken.split('.');
    segments[2] = `${segments[2][0] === 'A' ? 'B' : 'A'}${segments[2].slice(1)}`;
    this.check('mcp_rejects_tampered_access_token', await rpc('tools/list', {}, { bearer: segments.join('.') }), 401, 'invalid_token');
    this.check('mcp_rejects_hostile_origin', await rpc('tools/list', {}, { headers: { Origin: 'https://untrusted.invalid' } }), 403, 'invalid_origin');
    this.check('mcp_requires_initialize_before_tools', await rpc('tools/list'), 400);
    const initialized = await rpc('initialize', {
      protocolVersion: VERSION, capabilities: {},
      clientInfo: { name: 'shoten-real-http-mcp-client', version: '1.0.0' },
    });
    sessionId = initialized.headers.get('mcp-session-id');
    assert(sessionId);
    assert.equal(initialized.body.result.protocolVersion, VERSION);
    assert.deepEqual(initialized.body.result.capabilities.tools, { listChanged: false });
    this.check('mcp_initialize_negotiates_pinned_protocol_and_tools', initialized, 200);
    this.check('mcp_requires_initialized_notification', await rpc('tools/list'), 400);
    const notification = await http(this.resource, {
      method: 'POST', json: { jsonrpc: '2.0', method: 'notifications/initialized' }, bearer: accessToken,
      headers: {
        accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': VERSION, 'MCP-Session-Id': sessionId,
      },
    });
    assert.equal(notification.body, null);
    this.check('mcp_initialized_notification_returns_empty_202', notification, 202);
    this.check('mcp_rejects_unsupported_protocol_header', await rpc('tools/list', {}, { headers: { 'MCP-Protocol-Version': '2099-01-01' } }), 400);
    const tools = await rpc('tools/list');
    assert.equal(tools.body.result.tools[0].name, 'read_synthetic_document');
    this.check('mcp_tools_list_over_authenticated_streamable_http', tools, 200);
    const allowed = await rpc('tools/call', { name: 'read_synthetic_document', arguments: { documentId: 'alice' } });
    assert.equal(allowed.body.result.isError, false);
    assert.equal(allowed.body.result.content[0].type, 'text');
    this.check('mcp_tools_call_reads_authorized_synthetic_document', allowed, 200);
    const denied = await rpc('tools/call', { name: 'read_synthetic_document', arguments: { documentId: 'bob' } });
    assert.equal(denied.body.result.isError, true);
    this.check('mcp_tools_call_denies_other_synthetic_user_document', denied, 200);
    const invalidArgs = await rpc('tools/call', { name: 'read_synthetic_document', arguments: { documentId: 'alice', unexpected: true } });
    assert.equal(invalidArgs.body.error.code, -32602);
    this.check('mcp_invalid_tool_arguments_return_jsonrpc_error', invalidArgs, 200);
    this.check('mcp_get_explicitly_declines_optional_sse', await http(this.resource, {
      bearer: accessToken, headers: { accept: 'text/event-stream', 'MCP-Protocol-Version': VERSION, 'MCP-Session-Id': sessionId },
    }), 405);
    this.check('mcp_delete_terminates_session', await http(this.resource, {
      method: 'DELETE', bearer: accessToken,
      headers: { 'MCP-Protocol-Version': VERSION, 'MCP-Session-Id': sessionId },
    }), 204);
    this.check('mcp_terminated_session_returns_404', await rpc('tools/list'), 404);
    return {
      schema: 'shoten.entra-custom-broker-keycloak-mcp-results.v1',
      proof_status: 'prototype_core_flow_verified_not_ema_conformance',
      specification: {
        mcp_protocol_version: VERSION, ema_status: 'stable',
        ema_source_revision: EMA_REVISION,
        ema_source: `https://github.com/modelcontextprotocol/ext-auth/blob/${EMA_REVISION}/specification/stable/enterprise-managed-authorization.mdx`,
      },
      verified_entra_bootstrap: {
        real_signed_user_token: true, acquisition: 'supported Azure CLI; pre-existing login; one silent acquisition',
        signature_issuer_audience_expiry_tenant_user_verified: true,
        issuer: '<ENTRA_TENANT_ISSUER>', audience: '<OWN_API_A>',
        subject: '<SIGNED_IN_USER>', authorized_party: '<AZURE_CLI>', required_scope: 'access_as_user',
      },
      endpoints: {
        custom_broker_issuer: this.issuer, custom_broker_token: `${this.issuer}/token`,
        keycloak_receiver: this.receiverIssuer, mcp_resource: this.resource,
        protected_resource_metadata: this.metadataUrl,
      },
      verified_idjag_context: {
        issuer: '<CUSTOM_LOCAL_BROKER_NOT_ENTRA>', subject: '<MAPPED_VERIFIED_ENTRA_USER>',
        audience: this.receiverIssuer, client_id: this.clientId, resource: this.resource,
        scope: brokerJwt.claims.scope, typ: brokerJwt.header.typ, signature_verified: true,
      },
      verified_mcp_access_token_context: {
        issuer: this.receiverIssuer, subject: '<LINKED_LOCAL_USER>',
        authorized_party: accessClaims.azp, audience: accessClaims.aud,
        scope: accessClaims.scope, signature_verified: true,
      },
      token_inspection: inspectKeycloakPair(assertion, accessToken),
      verified_tool_result: allowed.body.result,
      receiver_advertises_idjag_grant_profile: advertised.includes('urn:ietf:params:oauth:grant-profile:id-jag'),
      tests: this.tests,
      passed: true,
      limitations: [
        'Real Entra own-API-A access token bootstraps a CUSTOM local broker. This is not native Entra ID-JAG issuance.',
        'Stable EMA uses an SSO ID token/refresh token or SAML assertion. This prototype deliberately uses an API-A user access token; no OIDC login UI or full standard EMA bootstrap is shown.',
        'Keycloak 26.8.1 experimental receiver targets documented ID-JAG draft-01; stable EMA references draft-04. No conformance or general interoperability certification.',
        'The one-resource receiver client is explicitly provisioned locally; fixed audience/scope mapping constrains output. Native validation of every later-draft resource/scope processing rule is not claimed.',
        'MCP 2025-11-25 JSON-response Streamable HTTP subset: initialize, initialized notification, tools/list, tools/call, session header, GET 405, DELETE. No SSE, resumability, sampling, prompts, elicitation, or full SDK compatibility certification.',
        'All documents are synthetic. Existing Azure CLI login is a prerequisite; no new Entra resources, permissions, interactive login, cache scraping or cloud mutations.',
        'Custom one-use bootstrap-token hash policy is lab policy, not Entra-native token revocation. Keycloak ID-JAG replay prevention is tested separately.',
        'HTTP loopback and static ephemeral-key trust are development-only. No production deployment, group-policy management UI, distributed replay or immediate cross-domain revocation is demonstrated.',
      ],
    };
  }

  async close() {
    for (const server of [this.mcpServer, this.brokerServer]) {
      if (server?.listening) {
        server.closeIdleConnections();
        await new Promise((resolve) => server.close(resolve));
      }
    }
    this.sessions.clear();
    this.usedInputTokens.clear();
    this.token = undefined;
    this.claims = undefined;
  }
}
