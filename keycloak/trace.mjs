import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

// Publication-safe evidence trace. Raw tokens stay inside the functions that summarize them;
// only allowlisted, masked fields are stored, rendered and self-checked.
export const TRACE_SCHEMA = 'shoten.lab-trace.v1';
const WIDTH = 132;
const SECRET_NAMES = new Set(['client_secret', 'password', 'refresh_token', 'client_assertion', 'secret']);
const JWT_LIKE = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/;
const GUID = /[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}/i;
const CLAIMS = {
  idjag: ['iss', 'sub', 'aud', 'client_id', 'resource', 'scope', 'iat', 'nbf', 'exp', 'jti', 'email'],
  access: ['iss', 'sub', 'aud', 'azp', 'typ', 'scope', 'iat', 'nbf', 'exp', 'jti', 'client_id'],
  entra: ['iss', 'aud', 'azp', 'scp', 'ver', 'iat', 'nbf', 'exp', 'tid', 'oid', 'sub'],
};
const KIND_LABEL = { idjag: 'ID-JAG token', entra: 'Entra access token', access: 'access token' };
const TIME_CLAIMS = new Set(['iat', 'nbf', 'exp']);
const SYNTHETIC_SUBJECT = /^[a-z][a-z0-9-]{2,40}$/;
const SYNTHETIC_KID = /^[a-z]+(?:-[a-z]+){1,4}$/;
const LIFETIME_CHECKS = new Set(['idjag_long_exp_with_iat_is_accepted_not_a_lifetime_cap', 'receiver_access_token_exp_limited_by_assertion']);

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
export const clock = (seconds) => `${new Date(seconds * 1000).toISOString().slice(11, 19)}Z`;
const clockMs = (iso) => String(iso).slice(11, 23);

export function sensitiveReason(text) {
  const value = String(text);
  if (/eyJ[A-Za-z0-9_-]{6,}/.test(value)) return 'jwt';
  if (GUID.test(value)) return 'guid';
  for (const run of value.match(/[A-Za-z0-9_-]{32,}/g) ?? []) {
    if (/[A-Z]/.test(run) && /[a-z]/.test(run) && /[0-9]/.test(run)) return 'opaque';
  }
  for (const email of value.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+/g) ?? []) {
    if (!/@example\.test$/i.test(email)) return 'email';
  }
  return null;
}

export function safeText(value, max = 240) {
  let text = typeof value === 'string' ? value : JSON.stringify(value);
  if (text === undefined) return '(none)';
  text = text.replace(/[^\x20-\x7E]/g, '?');
  if (sensitiveReason(text)) return '<omitted>';
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}

export function assertPublishableLines(lines) {
  assert(Array.isArray(lines) && lines.length > 0, 'EmptyTrace');
  for (const line of lines) {
    assert(typeof line === 'string' && /^[\x20-\x7E]*$/.test(line), 'NonAsciiTraceLine');
    assert(line.length <= 160, 'TraceLineTooLong');
    assert(!sensitiveReason(line), 'SensitiveTraceLine');
  }
  return lines;
}

function decodeJwt(jwt) {
  const parts = String(jwt).split('.');
  if (parts.length !== 3) return null;
  try {
    return {
      header: JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')),
      claims: JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')),
    };
  } catch {
    return null;
  }
}

function claimValue(kind, name, value, scrub) {
  if (TIME_CLAIMS.has(name)) return Number.isInteger(value) ? value : '[INVALID]';
  if (name === 'jti') return '[REDACTED]';
  if (name === 'sub') {
    if (kind === 'access') return '[LINKED_LOCAL_USER]';
    if (kind === 'idjag') return typeof value === 'string' && SYNTHETIC_SUBJECT.test(value) ? value : '[MAPPED_ENTRA_USER]';
    return '[REDACTED]';
  }
  if (Array.isArray(value)) return value.map((item) => safeText(scrub(String(item)), 120));
  return safeText(scrub(String(value)), 160);
}

function summarize(jwt, kind, scrub) {
  const decoded = decodeJwt(jwt);
  if (!decoded) return { kind, length: String(jwt).length, opaque: true };
  const summary = { kind, length: String(jwt).length, sha: createHash('sha256').update(String(jwt)).digest('hex').slice(0, 8), header: {}, claims: {} };
  if (typeof decoded.header.alg === 'string') summary.header.alg = safeText(decoded.header.alg, 16);
  if (typeof decoded.header.typ === 'string') summary.header.typ = safeText(decoded.header.typ, 40);
  if (decoded.header.kid !== undefined) summary.header.kid = SYNTHETIC_KID.test(String(decoded.header.kid)) ? String(decoded.header.kid) : '[REDACTED]';
  for (const name of CLAIMS[kind]) {
    if (Object.hasOwn(decoded.claims, name)) summary.claims[name] = claimValue(kind, name, decoded.claims[name], scrub);
  }
  return summary;
}

function formatClaim(name, value, claims) {
  if (TIME_CLAIMS.has(name) && Number.isInteger(value)) {
    const lifetime = name === 'exp' && Number.isInteger(claims.iat) ? ` (iat+${value - claims.iat}s)` : '';
    return `${name}=${clock(value)}${lifetime}`;
  }
  return Array.isArray(value) ? `${name}=[${value.join(', ')}]` : `${name}=${value}`;
}

export function layout(tokens, continuation, { first = continuation, width = WIDTH, separator = '  ' } = {}) {
  const lines = [];
  let line = first;
  let used = false;
  for (const token of tokens) {
    if (used && (line + separator + token).length > width) {
      lines.push(line);
      line = continuation + token;
    } else {
      line += (used ? separator : '') + token;
    }
    used = true;
  }
  if (used) lines.push(line);
  return lines;
}

export function wrapText(text, width = 124) {
  return layout(text.split(' '), '', { first: '', separator: ' ', width });
}

function fit(lines, width = WIDTH) {
  const out = [];
  for (const line of lines) {
    if (line.length <= width) {
      out.push(line);
      continue;
    }
    const indent = /^ */.exec(line)[0];
    out.push(...layout(line.slice(indent.length).split(' '), `${indent}        `, { first: indent, separator: ' ', width }));
  }
  return out;
}

function tokenLines(summary, indent) {
  if (summary.opaque) return [`${indent}(not a decodable JWT, ${summary.length} chars)`];
  const header = ['typ', 'alg', 'kid'].filter((name) => summary.header[name] !== undefined).map((name) => `${name}=${summary.header[name]}`);
  if (summary.sha) header.push(`sha256:${summary.sha}`);
  const out = layout(header, `${indent}        `, { first: `${indent}header  ` });
  const claims = Object.entries(summary.claims).map(([name, value]) => formatClaim(name, value, summary.claims));
  out.push(...layout(claims, `${indent}        `, { first: `${indent}claims  ` }));
  return out;
}

export function diffAssertion(base, current) {
  if (!base || !current || base.opaque || current.opaque) return '';
  const reference = base.claims.iat;
  const show = (name, value) => {
    if (value === undefined) return '(none)';
    if (TIME_CLAIMS.has(name) && Number.isInteger(value) && Number.isInteger(reference)) return relText(value - reference);
    const text = Array.isArray(value) ? `[${value.join(', ')}]` : String(value);
    return text.replace(/http:\/\/127\.0\.0\.1:\d+/g, '...');
  };
  const parts = [];
  if (base.header.typ !== current.header.typ) parts.push(`typ: ${current.header.typ ?? '(none)'}`);
  for (const name of CLAIMS.idjag) {
    const before = base.claims[name];
    const after = current.claims[name];
    if (JSON.stringify(before) === JSON.stringify(after)) continue;
    if (TIME_CLAIMS.has(name) && Number.isInteger(before) && Number.isInteger(after) && Math.abs(after - before) <= 2) continue;
    if (after === undefined) parts.push(`${name}: removed`);
    else if (before === undefined) parts.push(`${name}: added ${show(name, after)}`);
    else parts.push(`${name}: ${show(name, before)} -> ${show(name, after)}`);
  }
  return parts.join('; ');
}

export function parseKeycloakLog(text, realm) {
  const event = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}),(\d{3}) (WARN|DEBUG|INFO|ERROR)\s+\[org\.keycloak\.events\] \([^)]*\) (.*)$/;
  const access = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}),(\d{3}) INFO\s+\[org\.keycloak\.http\.access-log\] \([^)]*\) \S+ - - \[[^\]]+\] "([A-Z]+) (\/[^ ?"]*)(?:\?[^ "]*)? HTTP\/1\.[01]" (\d{3}) (?:\d+|-)$/;
  const pending = [];
  const groups = [];
  for (const line of String(text).split(/\r?\n/)) {
    const e = event.exec(line);
    if (e) {
      const fields = {};
      for (const match of e[5].matchAll(/([A-Za-z_]+)="((?:[^"\\]|\\.)*)"/g)) fields[match[1]] = match[2];
      if (fields.realmName === realm && /^[A-Z_]+$/.test(fields.type ?? '')) {
        pending.push({ time: `${e[2]}.${e[3]}`, level: e[4], fields });
      }
      continue;
    }
    const a = access.exec(line);
    if (a) {
      if (a[5].startsWith(`/realms/${realm}/`)) {
        groups.push({ access: { time: `${a[2]}.${a[3]}`, method: a[4], path: a[5], status: Number(a[6]) }, events: pending.splice(0) });
      } else {
        pending.length = 0;
      }
    }
  }
  return groups;
}

function keycloakEvent(raw, scrub) {
  const f = raw.fields;
  const pick = (name, max = 160) => (f[name] === undefined ? undefined : safeText(scrub(f[name]), max));
  const idpUser = f.identity_provider_user_id;
  const result = {
    time: raw.time, level: raw.level, type: safeText(f.type, 60), client: pick('clientId', 60),
  };
  if (f.error) result.error = pick('error', 60);
  if (f.reason) result.reason = pick('reason', 200);
  if (f.identity_provider) result.idp = pick('identity_provider', 60);
  if (f.identity_provider_issuer) result.idp_issuer = pick('identity_provider_issuer', 100);
  if (idpUser) result.idp_user = SYNTHETIC_SUBJECT.test(idpUser) ? safeText(idpUser, 60) : '[MAPPED_ENTRA_USER]';
  if (f.userId && f.userId !== 'null') result.local_user = f.username && SYNTHETIC_SUBJECT.test(f.username) ? `${safeText(f.username, 60)} ([LINKED_LOCAL_USER])` : '[LINKED_LOCAL_USER]';
  if (f.grant_type) result.grant_type = pick('grant_type', 100);
  if (f.requested_token_type) result.requested_token_type = pick('requested_token_type', 100);
  if (f.scope) result.scope = pick('scope', 80);
  return result;
}

function createRecorder() {
  return {
    enabled: false,
    entries: [],
    origins: new Map(),
    masks: [],
    secrets: [],
    baseline: null,
    reset() {
      Object.assign(this, { enabled: true, entries: [], origins: new Map(), masks: [], secrets: [], baseline: null });
    },
    mask(value, alias) {
      if (typeof value === 'string' && value.length >= 8) this.masks.push([new RegExp(escapeRegExp(value), 'gi'), value, alias]);
    },
    origin(origin, name) {
      this.origins.set(origin, name);
    },
    scrub(text) {
      let out = String(text);
      for (const [pattern, , alias] of this.masks) out = out.replace(pattern, alias);
      return out;
    },
    token(jwt, kind) {
      this.secrets.push(String(jwt));
      return summarize(jwt, kind, (text) => this.scrub(text));
    },
    kindOf(field, jwt) {
      const decoded = decodeJwt(jwt);
      if (decoded?.header?.typ === 'oauth-id-jag+jwt' || field === 'assertion') return 'idjag';
      if (String(decoded?.claims?.iss ?? '').includes('login.microsoftonline.com')) return 'entra';
      return 'access';
    },
    http({ method, url, form, json, bearer, headers = {}, status, body, responseHeaders, quiet = false }) {
      if (!this.enabled || quiet) return -1;
      const parsed = new URL(url);
      const entry = {
        kind: 'http', n: this.entries.length + 1,
        target: this.origins.get(parsed.origin) ?? (parsed.hostname === 'login.microsoftonline.com' ? 'entra' : 'other'),
        origin: this.scrub(parsed.origin), method, path: this.scrub(parsed.pathname),
        at: new Date().toISOString(), request: {}, response: { status },
      };
      if (form) {
        entry.request.form = [];
        for (const [name, value] of Object.entries(form)) {
          const text = String(value);
          if (SECRET_NAMES.has(name)) entry.request.form.push([name, '<redacted>']);
          else if (JWT_LIKE.test(text)) {
            entry.request.tokens ??= [];
            entry.request.tokens.push({ field: name, summary: this.token(text, this.kindOf(name, text)) });
            entry.request.form.push([name, `<JWT ${text.length} chars>`]);
          } else entry.request.form.push([name, safeText(this.scrub(text), 160)]);
        }
      }
      if (json) {
        entry.request.rpc = { method: safeText(json.method, 60) };
        if (json.params && Object.keys(json.params).length) entry.request.rpc.params = safeText(this.scrub(JSON.stringify(json.params)), 200);
      }
      if (bearer) {
        entry.request.bearer = JWT_LIKE.test(bearer)
          ? this.token(bearer, this.kindOf('bearer', bearer))
          : { kind: 'access', length: String(bearer).length, opaque: true };
      }
      const shown = [];
      const lowered = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
      for (const name of ['origin', 'mcp-protocol-version']) {
        if (lowered[name] !== undefined) shown.push([name, safeText(this.scrub(lowered[name]), 80)]);
      }
      if (shown.length) entry.request.headers = shown;
      this.describeResponse(entry, body, responseHeaders);
      this.entries.push(entry);
      return this.entries.length - 1;
    },
    describeResponse(entry, body, responseHeaders) {
      entry.response.fields = [];
      if (body && typeof body === 'object' && !Array.isArray(body)) {
        const plain = ['error', 'error_description', 'token_type', 'expires_in', 'scope', 'issued_token_type', 'active', 'client_id', 'resource', 'authorization_servers', 'issuer', 'token_endpoint', 'scopes_supported'];
        for (const [name, value] of Object.entries(body)) {
          if (name === 'access_token' && typeof value === 'string') {
            entry.response.tokens ??= [];
            entry.response.tokens.push({ field: name, summary: this.token(value, this.kindOf(name, value)) });
            entry.response.fields.push([name, `<JWT ${value.length} chars>`]);
          } else if (plain.includes(name) && typeof value !== 'object') entry.response.fields.push([name, safeText(this.scrub(String(value)), 200)]);
          else if (plain.includes(name) && Array.isArray(value)) entry.response.fields.push([name, safeText(this.scrub(value.join(', ')), 200)]);
        }
        if (Array.isArray(body.keys)) entry.response.fields.push(['keys', String(body.keys.length)]);
        if (Object.hasOwn(body, 'issuer') && Object.hasOwn(body, 'token_endpoint')) {
          const profiles = body.authorization_grant_profiles_supported;
          entry.response.fields.push(['authorization_grant_profiles_supported', Array.isArray(profiles) ? safeText(profiles.join(', '), 160) : '(absent)']);
        }
        if (Object.hasOwn(body, 'access_token')) entry.response.fields.push(['refresh_token', Object.hasOwn(body, 'refresh_token') ? '<present>' : '(absent)']);
        if (body.jsonrpc === '2.0') entry.response.rpc = this.describeRpc(entry.request.rpc?.method, body);
      }
      const shown = [];
      for (const name of ['www-authenticate', 'allow', 'mcp-session-id']) {
        const value = responseHeaders?.get?.(name);
        if (value) shown.push([name, name === 'mcp-session-id' ? '<redacted>' : safeText(this.scrub(value), 220)]);
      }
      if (shown.length) entry.response.headers = shown;
    },
    describeRpc(method, body) {
      if (body.error) return `error ${safeText(body.error.code, 12)} "${safeText(body.error.message, 80)}"`;
      const result = body.result ?? {};
      if (method === 'initialize') return `protocolVersion=${safeText(result.protocolVersion, 20)} server=${safeText(result.serverInfo?.name, 60)}/${safeText(result.serverInfo?.version, 12)}`;
      if (method === 'tools/list') return `tools=[${(result.tools ?? []).map((tool) => safeText(tool.name, 60)).join(', ')}]`;
      if (method === 'tools/call') return `isError=${result.isError === true} text="${safeText(result.content?.[0]?.text ?? '', 120)}"`;
      return safeText(JSON.stringify(result), 120);
    },
    name(index, name, label) {
      if (index >= 0 && this.entries[index]) Object.assign(this.entries[index], { name, ...(label ? { label } : {}) });
    },
    note(index, text) {
      if (index >= 0 && this.entries[index]) (this.entries[index].notes ??= []).push(safeText(this.scrub(text), 160));
    },
    local({ name, outcome, detail, token, label }) {
      if (!this.enabled) return;
      this.entries.push({
        kind: 'local', n: this.entries.length + 1, name, outcome,
        ...(label ? { label } : {}), ...(detail ? { detail: safeText(this.scrub(detail), 240) } : {}),
        ...(token ? { token } : {}),
      });
    },
    server({ source, method, path, status, outcome, reason, rpc, bearer }) {
      if (!this.enabled) return;
      const entry = {
        kind: 'server', n: this.entries.length + 1, source, method, path: safeText(this.scrub(path), 120),
        status, outcome, reason: safeText(this.scrub(reason ?? ''), 160), at: new Date().toISOString(),
      };
      if (rpc) entry.rpc = safeText(rpc, 60);
      if (bearer) {
        const decoded = decodeJwt(bearer);
        if (decoded) {
          this.secrets.push(bearer);
          entry.bearer = {
            typ: safeText(decoded.header.typ ?? '(none)', 40),
            iss: safeText(this.scrub(String(decoded.claims.iss ?? '(none)')), 120),
            aud: safeText(this.scrub(Array.isArray(decoded.claims.aud) ? decoded.claims.aud.join(', ') : String(decoded.claims.aud ?? '(none)')), 120),
          };
        } else entry.bearer = { typ: '(not a JWT)', iss: '(none)', aud: '(none)' };
      }
      this.entries.push(entry);
    },
    finalize({ keycloakLog, realm } = {}) {
      const entries = structuredClone(this.entries);
      for (const entry of entries) {
        if (entry.kind !== 'http' || !['issuer', 'mcp', 'resource'].includes(entry.target)) continue;
        const rpc = entry.request.rpc?.method ?? null;
        const candidates = entries.filter((e) => e.kind === 'server' && !e.matched && e.method === entry.method
          && e.path === entry.path && e.status === entry.response.status);
        const server = candidates.find((e) => (e.rpc ?? null) === rpc) ?? candidates.find((e) => e.rpc === undefined);
        if (!server) continue;
        server.matched = true;
        entry.server = {
          source: server.source, outcome: server.outcome, reason: server.reason, at: server.at,
          ...(server.rpc ? { rpc: server.rpc } : {}), ...(server.bearer ? { bearer: server.bearer } : {}),
        };
      }
      if (keycloakLog) {
        const groups = parseKeycloakLog(keycloakLog, realm);
        let position = 0;
        for (const entry of entries) {
          if (entry.kind !== 'http' || entry.target !== 'keycloak') continue;
          for (let i = position; i < groups.length; i++) {
            const g = groups[i];
            if (g.access.method === entry.method && g.access.path === entry.path && g.access.status === entry.response.status) {
              entry.keycloak = { access: g.access, events: g.events.map((raw) => keycloakEvent(raw, (text) => this.scrub(text))) };
              position = i + 1;
              break;
            }
          }
        }
      }
      const trace = { schema: TRACE_SCHEMA, entries: entries.filter((entry) => entry.kind !== 'server') };
      const serialized = JSON.stringify(trace);
      for (const [, value] of this.masks) assert(!serialized.toLowerCase().includes(value.toLowerCase()), 'TraceContainsKnownIdentifier');
      for (const secret of this.secrets) {
        const payload = secret.split('.')[1];
        assert(!serialized.includes(secret) && !(payload && payload.length > 16 && serialized.includes(payload)), 'TraceContainsTokenMaterial');
      }
      assert(!sensitiveReason(serialized.replace(/"(?:at|time)":"[^"]*"/g, '')), 'TraceLooksSensitive');
      return trace;
    },
  };
}

export const recorder = createRecorder();
export { createRecorder };

export const KEYCLOAK_CHECKS = {
  A: ['A valid ID-JAG token is exchanged for an access token', [
    ['idjag_receiver_accepts_valid_assertion', 'valid ID-JAG token'],
    ['idjag_exchange_returns_no_refresh_token', 'the response carries no refresh_token'],
    ['issued_access_token_signature_issuer_subject_client_audience_scope', 'the access token verifies against the realm keys (JWKS)'],
  ]],
  B: ['One condition of the ID-JAG token is broken at a time', [
    ['idjag_replay_rejected', 'same ID-JAG token sent again (same jti)'],
    ['idjag_client_binding_rejected', 'client_id claim names another client'],
    ['idjag_missing_client_binding_rejected', 'client_id claim removed'],
    ['idjag_missing_iat_rejected', 'iat claim removed'],
    ['idjag_missing_jti_rejected', 'jti claim removed'],
    ['idjag_missing_exp_rejected', 'exp claim removed'],
    ['idjag_wrong_audience_rejected', 'aud names another receiver'],
    ['idjag_multiple_audiences_rejected', 'aud has two values'],
    ['idjag_untrusted_issuer_rejected', 'iss is not a registered Identity Provider'],
    ['idjag_unlinked_subject_rejected', 'sub is not linked to a local user'],
    ['idjag_untrusted_signing_key_rejected', 'signed with a different RSA key (claims unchanged)'],
    ['idjag_expired_rejected', 'already expired'],
    ['idjag_future_nbf_rejected', 'nbf in the future'],
    ['idjag_future_iat_rejected', 'iat in the future'],
    ['idjag_too_old_iat_rejected', 'iat too far in the past'],
  ]],
  C: ['Client authentication, client settings and user mapping', [
    ['invalid_client_credentials_rejected', 'client_secret is wrong'],
    ['client_grant_disabled_rejected', 'client_id = grant-disabled-client (the grant is switched off for it)'],
    ['client_issuer_not_allowed_rejected', 'client_id = idp-not-allowed-client (this IdP is not allowed for it)'],
    ['idjag_missing_client_authentication_rejected', 'no client_secret sent'],
    ['idjag_public_client_rejected', 'client_id = public-lab-client (a public client, no client authentication)'],
    ['idjag_confidential_control_client_accepted', 'client_id = confidential-control-client (confidential; control)'],
    ['idjag_unlinked_subject_with_matching_email_rejected', 'sub = not-linked, email = the email of the linked user'],
    ['idjag_unlinked_subject_creates_no_user', 'user count before and after the unlinked requests'],
  ]],
  D: ['Validator selection by typ, and lifetime limits', [
    ['rfc7523_plain_jwt_without_client_id_accepted', 'typ = JWT; client_id and iat removed'],
    ['rfc7523_plain_jwt_mismatched_client_id_accepted', 'typ = JWT; client_id = another-client'],
    ['unrecognized_typ_uses_generic_jwt_validator', 'typ = not-idjag+jwt; client_id and iat removed'],
    ['idjag_long_exp_with_iat_is_accepted_not_a_lifetime_cap', 'exp = now+600s (iat present)'],
    ['rfc7523_long_exp_without_iat_rejected', 'typ = JWT; iat removed; exp = now+600s'],
    ['receiver_access_token_exp_limited_by_assertion', 'exp = now+30s: the access token must not outlive it'],
  ]],
  E: ['Introspection, token exchange and the resource server', [
    ['non_audience_client_introspection_reports_inactive', 'introspect as receiver-client (not in aud)'],
    ['resource_audience_access_token_introspection', 'introspect as lab-api (the audience)'],
    ['rfc8693_access_token_exchange_control', 'RFC 8693 exchange of the access token (control)'],
    ['native_idjag_issuance_via_rfc8693_not_supported', 'RFC 8693 exchange asking for an ID-JAG token'],
    ['resource_accepts_receiver_access_token', 'resource server: Bearer = Keycloak access token'],
    ['resource_rejects_identity_assertion_as_bearer', 'resource server: Bearer = ID-JAG token'],
    ['resource_rejects_missing_token', 'resource server: no Authorization header'],
    ['short_lived_access_token_accepted_before_expiry', 'resource server: access token from a 6 s ID-JAG token, right away'],
    ['short_lived_access_token_rejected_after_expiry', 'resource server: the same token 8 s later'],
    ['resource_audience_validation_rejects_another_api', 'the access token is not valid for another API (local check)'],
  ]],
  F: ['Container ownership checks (Docker only)', [
    ['container_name_collision_preserves_existing_owned_fixture', 'a name collision leaves the existing owned container alone'],
    ['collision_fixture_cleanup_uses_verified_exact_id', 'fixture cleanup removes only the verified container ID'],
  ]],
};

export const FEDERATED_CHECKS = {
  A: ['Entra sign-in token (real, verified in memory, never printed)', [
    ['real_entra_user_signature_issuer_audience_expiry_scope_verified', 'RS256 signature (Entra keys), iss, aud, exp, tid, oid, azp, scp'],
    ['real_entra_token_wrong_api_audience_rejected', 'same token, expected aud = [BACKEND_API]'],
    ['real_entra_token_missing_required_user_scope_rejected', 'same token, expected scope = unauthorized.synthetic.scope'],
  ]],
  B: ['Discovery and the challenge for a missing token', [
    ['mcp_missing_token_challenges_with_protected_resource_metadata', 'MCP server, no Authorization header'],
    ['mcp_rfc9728_protected_resource_metadata', 'protected resource metadata of the MCP server'],
    ['custom_broker_metadata', 'metadata of the custom Issuer'],
    ['native_keycloak_metadata_observed_without_fabricated_idjag_profile', 'Keycloak metadata (is an ID-JAG grant profile advertised?)'],
  ]],
  C: ['Custom Issuer: token exchange (Entra token -> ID-JAG token)', [
    ['broker_rejects_unregistered_target_audience', 'audience = Receiver issuer + "/wrong"'],
    ['broker_rejects_unapproved_resource', 'resource = MCP URL + "/wrong"'],
    ['broker_rejects_unapproved_scope', 'scope = mcp.admin'],
    ['broker_rejects_wrong_client_secret', 'wrong client_secret'],
    ['broker_rejects_invalid_subject_token', 'subject_token = not-a-token'],
    ['custom_broker_issues_and_client_verifies_real_entra_backed_idjag', 'valid request'],
    ['custom_broker_one_use_bootstrap_replay_policy', 'the same Entra token again'],
  ]],
  D: ['Keycloak Receiver: jwt-bearer grant (ID-JAG token -> access token)', [
    ['native_keycloak_accepts_idjag_and_issues_exact_mcp_audience_token', 'valid ID-JAG token'],
    ['native_keycloak_rejects_idjag_replay', 'the same ID-JAG token again'],
    ['real_keycloak_token_wrong_resource_audience_rejected', 'access token checked for aud = MCP URL + "/wrong" (local)'],
    ['real_keycloak_token_missing_required_admin_scope_rejected', 'access token checked for scope = mcp.admin (local)'],
  ]],
  E: ['MCP server: tokens that must not be accepted', [
    ['mcp_rejects_original_entra_token_as_resource_bearer', 'Bearer = the original Entra access token'],
    ['mcp_rejects_idjag_as_resource_bearer', 'Bearer = the ID-JAG token'],
    ['mcp_rejects_tampered_access_token', 'Bearer = access token with a changed signature'],
    ['mcp_rejects_hostile_origin', 'valid Bearer, Origin = https://untrusted.invalid'],
  ]],
  F: ['MCP server: protocol session with the Keycloak access token', [
    ['mcp_requires_initialize_before_tools', 'tools/list before initialize'],
    ['mcp_initialize_negotiates_pinned_protocol_and_tools', 'initialize'],
    ['mcp_requires_initialized_notification', 'tools/list before notifications/initialized'],
    ['mcp_initialized_notification_returns_empty_202', 'notifications/initialized'],
    ['mcp_rejects_unsupported_protocol_header', 'MCP-Protocol-Version = 2099-01-01'],
    ['mcp_tools_list_over_authenticated_streamable_http', 'tools/list'],
    ['mcp_tools_call_reads_authorized_synthetic_document', 'tools/call documentId=alice'],
    ['mcp_tools_call_denies_other_synthetic_user_document', 'tools/call documentId=bob'],
    ['mcp_invalid_tool_arguments_return_jsonrpc_error', 'tools/call with an unexpected argument'],
    ['mcp_get_explicitly_declines_optional_sse', 'GET (optional SSE stream)'],
    ['mcp_delete_terminates_session', 'DELETE (end the session)'],
    ['mcp_terminated_session_returns_404', 'tools/list on the ended session'],
  ]],
  G: ['Container ownership checks (Docker only)', KEYCLOAK_CHECKS.F[1]],
};

function resultText(entry) {
  if (entry.kind === 'local') return entry.outcome === 'ok' ? 'ok' : 'rejected';
  const field = (name) => entry.response.fields.find(([key]) => key === name)?.[1];
  const error = field('error');
  const active = field('active');
  const profiles = field('authorization_grant_profiles_supported');
  const rpcCode = entry.response.rpc?.match(/^error (-?\d+)/)?.[1];
  const rpc = rpcCode ? ` JSON-RPC error ${rpcCode}` : '';
  return `HTTP ${entry.response.status}${error ? ` ${error}` : ''}${active ? ` active=${active}` : ''}${profiles ? ` authorization_grant_profiles_supported=${profiles}` : ''}${rpc}`;
}

function keycloakEventLine(event, indent, base) {
  const same = (name) => base && base[name] === event[name];
  const rest = [
    event.client && !same('client') && `client=${event.client}`,
    event.idp && !same('idp') && `idp=${event.idp}`,
    event.idp_user && !same('idp_user') && `idp_user=${event.idp_user}`,
    event.local_user && !same('local_user') && `local_user=${event.local_user}`,
    event.error && `error=${event.error}`,
    event.scope && !same('scope') && `scope="${event.scope}"`,
    event.requested_token_type && !same('requested_token_type') && `requested_token_type=${event.requested_token_type}`,
    event.reason && `reason="${event.reason}"`,
  ].filter(Boolean);
  if (!rest.length) rest.push(base ? 'same client, idp, idp_user and local_user as above' : '(no further fields)');
  return layout(rest, `${indent}    `, { first: `${indent}Keycloak ${event.time} ${event.level.padEnd(5)} ${event.type}  ` });
}

function evidenceLines(entry, indent, { baseEvent, access = false, seen, noBearer = false } = {}) {
  const lines = [];
  const description = entry.response?.fields?.find(([name]) => name === 'error_description')?.[1];
  const logged = entry.server?.reason ?? entry.keycloak?.events?.find((event) => event.reason)?.reason;
  if (description && (entry.keycloak || entry.server) && description !== logged) lines.push(`${indent}response error_description="${description}"`);
  if (entry.keycloak) {
    for (const event of entry.keycloak.events) lines.push(...keycloakEventLine(event, indent, baseEvent));
    const a = entry.keycloak.access;
    if (access || !entry.keycloak.events.length) lines.push(`${indent}Keycloak ${a.time} INFO  access log: ${a.method} ${a.path} ${a.status}`);
  } else if (entry.server && (entry.server.reason || entry.server.bearer || entry.server.rpc)) {
    const s = entry.server;
    const key = s.bearer ? `${s.bearer.typ}|${s.bearer.iss}|${s.bearer.aud}` : '';
    const repeated = key && seen?.has(key);
    if (key) seen?.add(key);
    const bearer = s.bearer && !repeated && !noBearer ? ` Bearer: typ=${s.bearer.typ} iss=${s.bearer.iss} aud=${s.bearer.aud}` : '';
    const first = `${s.source} server log ${clockMs(s.at)}${s.rpc ? ` rpc=${s.rpc}` : ''}${bearer}`;
    lines.push(...layout(first.split(' '), `${indent}    `, { first: indent, separator: ' ' }));
    lines.push(...layout(`-> ${s.outcome}${s.reason ? `: ${withGloss(s.reason)}` : ''}`.split(' '), `${indent}    `, { first: `${indent}    `, separator: ' ' }));
  } else if (entry.response.fields.some(([name]) => name === 'error_description')) {
    const description = entry.response.fields.find(([name]) => name === 'error_description')[1];
    lines.push(`${indent}reason: "${description}"`);
  }
  return lines;
}

function lifetimeLine(entry) {
  const assertion = entry.request?.tokens?.find((token) => token.field === 'assertion')?.summary?.claims;
  const access = entry.response?.tokens?.find((token) => token.field === 'access_token')?.summary?.claims;
  if (!assertion || !access || ![assertion.iat, assertion.exp, access.iat, access.exp].every(Number.isInteger)) return null;
  return `ID-JAG token exp=${clock(assertion.exp)} (iat+${assertion.exp - assertion.iat}s); access token exp=${clock(access.exp)} (iat+${access.exp - access.iat}s)`;
}

const REASON_GLOSS = {
  UnknownSigningKey: 'no key with this kid in the realm JWKS',
  InvalidJwtSignature: 'the signature does not verify with that key',
  InvalidJwt: 'not a well-formed JWT',
  InvalidJwtAlgorithm: 'alg is not RS256 or kid is missing',
  WrongIssuer: 'iss is not the expected issuer',
  WrongAudience: 'aud is not the expected audience',
  ExpiredJwt: 'exp is in the past',
  JwtNotYetValid: 'nbf is in the future',
  InvalidIssuedAt: 'iat is in the future',
  MissingBearer: 'the request has no Bearer token',
  MissingMcpScope: 'scope mcp.read is missing',
};

function withGloss(text) {
  return String(text).replace(/\((\w+)\)/g, (match, code) => (REASON_GLOSS[code] ? `(${code}: ${REASON_GLOSS[code]})` : match));
}

function plainValue(name, value) {
  if (value === undefined) return '(none)';
  if (TIME_CLAIMS.has(name) && Number.isInteger(value)) return clock(value);
  return Array.isArray(value) ? `[${value.join(', ')}]` : String(value);
}

// Offset of a time claim from the moment the request was sent (the server's "now"); small offsets are rounded as noise.
function relText(delta) {
  const rounded = Math.abs(delta) <= 2 ? 0 : (Math.abs(delta) >= 30 ? Math.round(delta / 5) * 5 : delta);
  return rounded === 0 ? 'now' : `now${rounded > 0 ? '+' : '-'}${Math.abs(rounded)}s`;
}

// Claims of a token; with a valid base token, the changed claims are listed separately with the valid value.
function claimItems(summary, base, { sentAt, baseSentAt } = {}) {
  const items = [];
  const changedItems = [];
  for (const name of CLAIMS[summary.kind]) {
    const value = summary.claims[name];
    const was = base?.claims?.[name];
    if (value === undefined && (!base || was === undefined)) continue;
    const timed = TIME_CLAIMS.has(name) && Number.isInteger(sentAt) && Number.isInteger(baseSentAt);
    const valueRel = timed && Number.isInteger(value) ? value - sentAt : null;
    const wasRel = timed && Number.isInteger(was) ? was - baseSentAt : null;
    const same = !base || JSON.stringify(value) === JSON.stringify(was)
      || (valueRel !== null && wasRel !== null && Math.abs(valueRel - wasRel) <= 3);
    if (same) {
      items.push(formatClaim(name, value, summary.claims));
      continue;
    }
    const valid = wasRel !== null ? relText(wasRel) : plainValue(name, was);
    const shown = `${plainValue(name, value)}${valueRel !== null ? ` (${relText(valueRel)})` : ''}`;
    const text = value === undefined ? `${name}=(removed) [valid: ${valid}]`
      : (was === undefined ? `${name}=${shown} [not in the valid token]` : `${name}=${shown} [valid: ${valid}]`);
    items.push(text);
    changedItems.push(text);
  }
  return { items, changedItems };
}

function tokenBlock(summary, indent, { ctx, where, label = 'token', base, baseWhere, at, times } = {}) {
  if (summary.opaque) return [`${indent}${label}: (not a decodable JWT, ${summary.length} chars)`];
  const sent = at ? `, sent ${at}` : '';
  const prior = ctx.seen.get(summary.sha);
  if (prior) return [`${indent}${label}: same JWT as the ${prior} (sha256:${summary.sha}${sent})`];
  register(ctx, summary, where);
  const { items, changedItems } = claimItems(summary, base, times);
  const pad = ' '.repeat(label.length + 2);
  if (base) {
    if (base.header.typ !== summary.header.typ) changedItems.unshift(`typ=${summary.header.typ ?? '(none)'} [valid: ${base.header.typ ?? '(none)'}]`);
    if (!changedItems.length) {
      return [`${indent}${label}: same header and claims as the ${baseWhere} (a new token, sha256:${summary.sha}${sent})`];
    }
    return [
      `${indent}${label}: JWT sha256:${summary.sha}${sent}; same as the ${baseWhere} except`,
      ...layout(changedItems, `${indent}${pad}`, { first: `${indent}${pad}` }),
    ];
  }
  const header = ['typ', 'alg', 'kid'].filter((name) => summary.header[name] !== undefined).map((name) => `${name}=${summary.header[name]}`);
  header.push(`sha256:${summary.sha}${sent}`);
  return [
    ...layout(header, `${indent}${pad}        `, { first: `${indent}${label}: header  ` }),
    ...layout(items, `${indent}${pad}        `, { first: `${indent}${pad}claims  ` }),
  ];
}

const SHOW_RESPONSE_TOKENS = new Set([
  'custom_broker_issues_and_client_verifies_real_entra_backed_idjag',
  'native_keycloak_accepts_idjag_and_issues_exact_mcp_audience_token',
]);

const BEARER_CLAIMS = ['iss', 'aud', 'azp', 'scope', 'scp', 'exp'];
const toList = (value) => (Array.isArray(value) ? value : String(value).split(/\s+/)).filter(Boolean);
const matches = (name, now, want) => (['aud', 'scope', 'scp'].includes(name)
  ? toList(want).every((item) => toList(now).includes(item))
  : JSON.stringify(now) === JSON.stringify(want));

// The Bearer token of a request to a resource server; every claim it must have and does not is followed by the required value.
function bearerBlock(summary, indent, { ctx, where, expected = {}, at, sentAt }) {
  if (summary.opaque) return [`${indent}Authorization: Bearer <not a JWT, ${summary.length} chars>`];
  const prior = ctx.seen.get(summary.sha);
  const twin = prior || summary.kind !== 'access' ? undefined : ctx.claimsSeen.get(JSON.stringify([summary.header, summary.claims]));
  register(ctx, summary, where);
  const relation = prior ? `, same JWT as the ${prior}` : (twin ? `, same claims as the ${twin}; a different JWT` : '');
  const out = [`${indent}Authorization: Bearer <JWT ${summary.length} chars${at ? `, sent ${at}` : ''}${relation}>`];
  const inner = `${indent}  `;
  const header = ['typ', 'alg', 'kid'].filter((name) => summary.header[name] !== undefined).map((name) => `${name}=${summary.header[name]}`);
  header.push(`sha256:${summary.sha}`);
  out.push(...layout(header, `${inner}        `, { first: `${inner}header  ` }));
  const items = [];
  for (const name of BEARER_CLAIMS) {
    const now = summary.claims[name];
    const want = expected[name];
    if (now === undefined && want === undefined) continue;
    if (want !== undefined && (now === undefined || !matches(name, now, want))) {
      items.push(`${name}=${plainValue(name, now)} [required: ${plainValue(name, want)}]`);
    } else if (name === 'exp' && Number.isInteger(now) && Number.isInteger(sentAt) && now <= sentAt) {
      items.push(`${formatClaim(name, now, summary.claims)} [required: after ${clock(sentAt)} (now)]`);
    } else items.push(formatClaim(name, now, summary.claims));
  }
  out.push(...layout(items, `${inner}        `, { first: `${inner}claims  ` }));
  return out;
}

// What differs from the valid request, the tokens that were sent, and (selected cases) the tokens returned.
function sentLines(entry, { no, ctx, base, baseForm, showBearer }) {
  const indent = '      ';
  const out = [];
  const at = `${String(entry.at).slice(11, 19)}Z`;
  for (const note of entry.notes ?? []) out.push(`${indent}sent: ${note}`);
  for (const [name, value] of entry.request.headers ?? []) {
    if (ctx.normalHeaders?.get(name) !== value) out.push(`${indent}sent header ${name}: ${value}`);
  }
  if (baseForm && entry.request.form) {
    const form = new Map(entry.request.form);
    for (const [name, value] of form) {
      const was = baseForm.get(name);
      if (was === value || (value.startsWith('<JWT') && String(was).startsWith('<JWT'))) continue;
      out.push(...layout([`sent: ${name}=${value}`, was === undefined ? '[not in the valid request]' : `[valid: ${was}]`], `${indent}      `, { first: indent, separator: ' ' }));
    }
    for (const [name, was] of baseForm) {
      if (!form.has(name)) out.push(`${indent}sent: ${name} is not sent [valid: ${was}]`);
    }
  }
  for (const token of entry.request.tokens ?? []) {
    const b = base?.get(token.field);
    const times = { sentAt: Math.floor(Date.parse(entry.at) / 1000), baseSentAt: ctx.baseSentAt };
    out.push(...tokenBlock(token.summary, indent, { ctx, where: `${token.field} of ${no}`, label: token.field, base: b?.summary, baseWhere: b?.where, at, times }));
  }
  if (showBearer && entry.request.bearer) {
    out.push(...bearerBlock(entry.request.bearer, indent, { ctx, where: `Bearer of ${no}`, expected: ctx.expected, at, sentAt: Math.floor(Date.parse(entry.at) / 1000) }));
  }
  if (SHOW_RESPONSE_TOKENS.has(entry.name)) {
    for (const token of entry.response.tokens ?? []) {
      const label = `${KIND_LABEL[token.summary.kind]} returned`;
      out.push(...tokenBlock(token.summary, indent, { ctx, where: `${KIND_LABEL[token.summary.kind]} returned by ${no}`, label }));
    }
  }
  return out;
}

function caseLines(index, entry, label, { expand = false, baseEvent, ctx, base, baseForm, showBearer = false } = {}) {
  const no = String(index).padStart(2, '0');
  const result = resultText(entry);
  const labelLines = layout(label.split(' '), '      ', { first: ` ${no} `, width: 84, separator: ' ' });
  const last = labelLines.length - 1;
  labelLines[last] = `${labelLines[last].padEnd(87)}-> ${result}`;
  const out = [...labelLines];
  if (entry.kind === 'local') {
    if (entry.token) {
      const label = KIND_LABEL[entry.token.kind] ?? 'token';
      out.push(...tokenBlock(entry.token, '      ', { ctx, where: `${label} of ${no}`, label }));
    }
    if (entry.detail) out.push(...layout(entry.detail.split(' '), '      ', { first: '      ', separator: ' ' }));
  } else if (expand) {
    out.push(...exchangeLines(entry, { ctx, no }));
  } else {
    out.push(...sentLines(entry, { no, ctx, base, baseForm, showBearer }));
    const lifetime = LIFETIME_CHECKS.has(entry.name) ? lifetimeLine(entry) : null;
    if (lifetime) out.push(`      ${lifetime}`);
    out.push(...evidenceLines(entry, '      ', { baseEvent, seen: ctx.bearerSeen, noBearer: showBearer }));
  }
  return out;
}

const wrapped = (text) => wrapText(text, 118).map((line) => `    ${line}`);

// Short statement of what the server accepts, so that the rejected values in the section are easy to judge.
function legendLines(kind, id, { byName, baseEntry, expected }) {
  const claimsOf = (name, where) => {
    const entry = byName.get(name);
    return (where === 'response' ? entry?.response?.tokens?.[0]?.summary : entry?.request?.tokens?.[0]?.summary)?.claims ?? {};
  };
  if (kind === 'keycloak') {
    const valid = claimsOf('idjag_receiver_accepts_valid_assertion', 'request');
    if (id === 'B') {
      return wrapped(`Keycloak accepts only: iss=${valid.iss} (signed with the registered key), aud=${valid.aud}, client_id=${valid.client_id}, a jti it has not seen, and an iat not older than 180 s.`);
    }
    if (id === 'C') {
      return wrapped('receiver-client is a confidential client with the JWT Authorization Grant on and only the Identity Provider custom-idjag-issuer allowed. grant-disabled-client has the grant off, idp-not-allowed-client does not allow the Identity Provider, public-lab-client is a public client, confidential-control-client has the same settings as the public one but is confidential.');
    }
    if (id === 'E') {
      return wrapped(`The resource server accepts a Bearer only if its kid is in the realm JWKS, the signature verifies, iss=${expected.iss}, azp=${expected.azp}, aud includes ${expected.aud}, scope includes ${expected.scope}, and exp is in the future.`);
    }
    return [];
  }
  const form = new Map(baseEntry?.request?.form ?? []);
  if (id === 'C') {
    return wrapped(`The Issuer accepts only: audience=${form.get('audience')}, resource=${form.get('resource')}, scope=${form.get('scope')}, client_id=${form.get('client_id')} with its secret, and a valid Entra access token that it has not exchanged before.`);
  }
  if (id === 'E') {
    return wrapped(`The MCP server accepts a Bearer only if its kid is in the Keycloak realm JWKS, the signature verifies, iss=${expected.iss}, azp=${expected.azp}, aud=${expected.aud}, scope includes ${expected.scope}, and exp is in the future.`);
  }
  return [];
}

function findBase(entries) {
  return entries.find((e) => e.kind === 'http' && e.name === 'idjag_receiver_accepts_valid_assertion')?.request.tokens?.find((t) => t.field === 'assertion')?.summary;
}

// The claims a resource server requires, taken from the valid exchange of the same run.
function expectedBearer(kind, byName) {
  const claimsOf = (name, where) => {
    const entry = byName.get(name);
    return (where === 'response' ? entry?.response?.tokens?.[0]?.summary : entry?.request?.tokens?.[0]?.summary)?.claims ?? {};
  };
  const pick = (claims) => Object.fromEntries(Object.entries(claims).filter(([, value]) => value !== undefined));
  if (kind === 'keycloak') {
    const offered = claimsOf('idjag_receiver_accepts_valid_assertion', 'request');
    return pick({ iss: claimsOf('idjag_receiver_accepts_valid_assertion', 'response').iss, azp: offered.client_id, aud: offered.resource, scope: offered.scope });
  }
  const issued = claimsOf('custom_broker_issues_and_client_verifies_real_entra_backed_idjag', 'response');
  return pick({ iss: claimsOf('native_keycloak_accepts_idjag_and_issues_exact_mcp_audience_token', 'response').iss, azp: issued.client_id, aud: issued.resource, scope: issued.scope });
}

function checksView(entries, sections, { header, kind, baseline, baseName, expand = [] }) {
  const byName = new Map(entries.filter((e) => e.name).map((e) => [e.name, e]));
  const baseEvent = byName.get(baseName)?.keycloak?.events?.[0];
  const baseEntry = byName.get(kind === 'keycloak' ? 'idjag_receiver_accepts_valid_assertion' : 'custom_broker_issues_and_client_verifies_real_entra_backed_idjag');
  const baseForm = new Map(baseEntry?.request?.form ?? []);
  const base = kind === 'keycloak'
    ? new Map((baseEntry?.request?.tokens ?? []).map((t) => [t.field, { summary: t.summary, where: `${t.field} of 01` }]))
    : undefined;
  const formSections = kind === 'keycloak' ? ['B', 'C', 'D'] : ['C'];
  const ctx = {
    byName, baseEntry, expected: expectedBearer(kind, byName), seen: new Map(), claimsSeen: new Map(), bearerSeen: new Set(),
    baseSentAt: baseEntry?.at ? Math.floor(Date.parse(baseEntry.at) / 1000) : undefined,
    normalHeaders: new Map(byName.get('mcp_initialize_negotiates_pinned_protocol_and_tools')?.request?.headers ?? []),
  };
  const lines = [...header, ''];
  let index = 0;
  let missing = 0;
  for (const [id, [title, checks]] of Object.entries(sections)) {
    lines.push(`[${id}] ${title}`);
    lines.push(...legendLines(kind, id, ctx));
    for (const [name, label] of checks) {
      index += 1;
      const entry = byName.get(name);
      if (!entry) {
        missing += 1;
        lines.push(` ${String(index).padStart(2, '0')} ${label}  -> (no trace recorded)`);
        continue;
      }
      let text = entry.label ?? label;
      const assertion = entry.request?.tokens?.find((t) => t.field === 'assertion')?.summary;
      const diff = baseline && id === 'B' ? diffAssertion(baseline, assertion) : '';
      if (diff) text = diff;
      lines.push(...caseLines(index, entry, text, {
        expand: expand.includes(name), baseEvent, ctx, base: formSections.includes(id) ? base : undefined,
        baseForm: formSections.includes(id) ? baseForm : undefined, showBearer: id === 'E',
      }));
    }
    lines.push('');
  }
  return { lines, count: index, missing };
}

function register(ctx, summary, where) {
  if (!ctx || summary.opaque) return;
  if (!ctx.seen.has(summary.sha)) ctx.seen.set(summary.sha, where);
  const key = JSON.stringify([summary.header, summary.claims]);
  if (!ctx.claimsSeen.has(key)) ctx.claimsSeen.set(key, where);
}

function exchangeLines(entry, { title, sameAs = {}, ctx, no } = {}) {
  const lines = [];
  const url = `${entry.origin}${entry.path}`;
  lines.push(` -> ${entry.method} ${url}${title ? `   (${title})` : ''}`);
  if (entry.request.headers) lines.push(...layout(entry.request.headers.map(([k, v]) => `${k}: ${v}`), '      ', { first: '      ' }));
  if (entry.request.bearer) {
    const b = entry.request.bearer;
    lines.push(`      Authorization: Bearer <${b.opaque ? 'opaque token' : `JWT ${b.length} chars`}: ${KIND_LABEL[b.kind] ?? 'token'}>`);
    if (!b.opaque) lines.push(...tokenLines(b, '        '));
  }
  if (entry.request.form) lines.push(...layout(entry.request.form.map(([k, v]) => `${k}=${v}`), '      ', { first: '      ' }));
  for (const token of entry.request.tokens ?? []) {
    if (sameAs[token.field]) {
      lines.push(`      ${token.field} is ${sameAs[token.field]}${token.summary.sha ? ` (sha256:${token.summary.sha})` : ''}`);
      continue;
    }
    lines.push(`      ${token.field} is an ${KIND_LABEL[token.summary.kind] ?? 'token'}:`);
    lines.push(...tokenLines(token.summary, '        '));
    register(ctx, token.summary, `${token.field} of ${no}`);
  }
  if (entry.request.rpc) lines.push(`      rpc ${entry.request.rpc.method}${entry.request.rpc.params ? ` ${entry.request.rpc.params}` : ''}`);
  lines.push(` <- HTTP ${entry.response.status}  ${clockMs(entry.at)} UTC`);
  if (entry.response.fields.length) lines.push(...layout(entry.response.fields.map(([k, v]) => `${k}=${v}`), '      ', { first: '      ' }));
  if (entry.response.headers) lines.push(...layout(entry.response.headers.map(([k, v]) => `${k}: ${v}`), '        ', { first: '      ' }));
  if (entry.response.rpc) lines.push(`      rpc result: ${entry.response.rpc}`);
  for (const token of entry.response.tokens ?? []) {
    lines.push(`      ${token.field} is an ${KIND_LABEL[token.summary.kind] ?? 'token'}:`);
    lines.push(...tokenLines(token.summary, '        '));
    register(ctx, token.summary, `${KIND_LABEL[token.summary.kind] ?? 'token'} returned by ${no}`);
  }
  lines.push(...evidenceLines(entry, '      ', { access: true }));
  return lines;
}

function runtimeHeader(report) {
  const container = String(report.cleanup?.container_id ?? '').slice(0, 12);
  const digest = String(report.runtime?.image_digest ?? '').replace('sha256:', '').slice(0, 12);
  return `Keycloak ${safeText(report.runtime?.keycloak, 20)} (image sha256:${safeText(digest, 12)}...) in a one-time container ${safeText(container, 12)}; times are UTC`;
}

export function renderKeycloakView(report) {
  assert(report?.trace?.schema === TRACE_SCHEMA, 'MissingTrace');
  const entries = report.trace.entries;
  const header = [
    runtimeHeader(report),
    'Realm idjag-receiver-lab. Keycloak is real; the ID-JAG tokens are signed by this script with a throw-away RSA key.',
    'now = the time the request is sent. "[valid: x]" = the value in the valid token of case 01. sha256 = fingerprint of the whole JWT.',
    'A response error_description equals the logged reason unless shown on its own line.',
  ];
  const view = checksView(entries, KEYCLOAK_CHECKS, {
    header, kind: 'keycloak', baseline: findBase(entries), baseName: 'idjag_receiver_accepts_valid_assertion', expand: ['idjag_receiver_accepts_valid_assertion'],
  });
  assert(view.missing === 0, 'IncompleteTrace');
  view.lines.push(`Verified current run: ${view.count} / ${report.tests.length} checks matched their expected results.`);
  return assertPublishableLines(fit(view.lines));
}

export function renderFederatedView(report) {
  assert(report?.trace?.schema === TRACE_SCHEMA, 'MissingTrace');
  const entries = report.trace.entries;
  const header = [
    runtimeHeader(report),
    'Real Entra sign-in token -> custom Issuer -> Keycloak Receiver -> MCP server, all but Entra on 127.0.0.1.',
    'now = the time the request is sent. "[valid: x]" = the value in the valid request. sha256 = fingerprint of the whole JWT.',
    '"server log" lines come from the Issuer / MCP server of this run.',
    'A response error_description equals the logged reason unless shown on its own line.',
  ];
  const { lines, count, missing } = checksView(entries, FEDERATED_CHECKS, { header, kind: 'federated', baseline: null });
  assert(missing === 0, 'IncompleteTrace');
  lines.push(`Verified current run: ${count} / ${report.tests.length} checks matched their expected results.`);
  return assertPublishableLines(fit(lines));
}

export function renderFederatedRunView(report) {
  assert(report?.trace?.schema === TRACE_SCHEMA, 'MissingTrace');
  const entries = report.trace.entries;
  const get = (name) => entries.find((e) => e.name === name);
  const need = (name) => { const entry = get(name); assert(entry, `MissingTraceEntry:${name}`); return entry; };
  const lines = [runtimeHeader(report)];
  const portOf = (entry) => entry.origin.replace('http://127.0.0.1:', '');
  const issuerEntry = need('custom_broker_issues_and_client_verifies_real_entra_backed_idjag');
  const receiverEntry = need('native_keycloak_accepts_idjag_and_issues_exact_mcp_audience_token');
  const mcpEntry = need('mcp_tools_list_over_authenticated_streamable_http');
  lines.push(`Loopback ports of this run: Keycloak ${portOf(receiverEntry)}, custom Issuer ${portOf(issuerEntry)}, MCP server ${portOf(mcpEntry)}. Entra is the only remote service.`);
  lines.push('Steps are grouped by purpose; the clock times show the actual order of the requests.', '');
  const entra = need('real_entra_user_signature_issuer_audience_expiry_scope_verified');
  const ctx = {
    seen: new Map(), claimsSeen: new Map(), bearerSeen: new Set(),
    expected: expectedBearer('federated', new Map(entries.filter((e) => e.name).map((e) => [e.name, e]))),
  };
  lines.push('[1] Entra sign-in token (real; read once with the existing Azure CLI login, verified, never printed)');
  lines.push('      az account get-access-token --scope api://[AI_AGENT_APP]/access_as_user');
  for (const name of ['entra_openid_configuration', 'entra_signing_keys']) {
    const e = get(name);
    if (e) lines.push(`      ${e.method} ${e.origin}${e.path} -> HTTP ${e.response.status}`);
  }
  lines.push(...tokenLines(entra.token, '      '));
  register(ctx, entra.token, 'Entra access token of step [1]');
  lines.push('      verified in memory: RS256 signature with the Entra keys, iss, aud, exp, tid, oid, azp, scp', '');
  lines.push('[2] Client -> custom Issuer: exchange the Entra token for an ID-JAG token (RFC 8693)');
  lines.push(...exchangeLines(issuerEntry, { sameAs: { subject_token: 'the Entra access token of step [1]' }, ctx, no: 'step [2]' }), '');
  lines.push('[3] Client -> Keycloak (Receiver): exchange the ID-JAG token for an access token (RFC 7523 jwt-bearer)');
  lines.push(...exchangeLines(receiverEntry, { sameAs: { assertion: 'the ID-JAG token of step [2]' }, ctx, no: 'step [3]' }), '');
  const firstBearer = need('mcp_initialize_negotiates_pinned_protocol_and_tools').request.bearer;
  const bearerNote = firstBearer?.sha && firstBearer.sha === receiverEntry.response.tokens?.[0]?.summary?.sha
    ? ` (the access token of step [3], sha256:${firstBearer.sha})` : '';
  lines.push(`[4] Client -> MCP server with the Keycloak access token as Bearer${bearerNote}`);
  const seenBearers = new Set();
  for (const name of ['mcp_initialize_negotiates_pinned_protocol_and_tools', 'mcp_initialized_notification_returns_empty_202', 'mcp_tools_list_over_authenticated_streamable_http', 'mcp_tools_call_reads_authorized_synthetic_document', 'mcp_tools_call_denies_other_synthetic_user_document']) {
    const e = need(name);
    lines.push(` -> POST ${e.origin}${e.path}  rpc ${e.request.rpc.method}${e.request.rpc.params ? ` ${e.request.rpc.params}` : ''}`);
    lines.push(`    <- HTTP ${e.response.status}${e.response.rpc ? `  ${e.response.rpc}` : ''}`);
    lines.push(...evidenceLines(e, '       ', { seen: seenBearers }));
  }
  lines.push('');
  lines.push('[5] The same MCP server refuses the tokens that are not its access token');
  lines.push(...legendLines('federated', 'E', { expected: ctx.expected }));
  for (const name of ['mcp_rejects_original_entra_token_as_resource_bearer', 'mcp_rejects_idjag_as_resource_bearer']) {
    const e = need(name);
    lines.push(` -> POST ${e.origin}${e.path}  rpc ${e.request.rpc.method}`);
    lines.push(...bearerBlock(e.request.bearer, '      ', {
      ctx, where: `Bearer of ${name}`, expected: ctx.expected, at: `${String(e.at).slice(11, 19)}Z`, sentAt: Math.floor(Date.parse(e.at) / 1000),
    }));
    lines.push(`    <- HTTP ${e.response.status} ${e.response.fields.find(([n]) => n === 'error')?.[1] ?? ''}`);
    if (e.response.headers) lines.push(...layout(e.response.headers.map(([k, v]) => `${k}: ${v}`), '        ', { first: '      ' }));
    lines.push(...evidenceLines(e, '      ', { noBearer: true }));
  }
  lines.push('', `Verified current run: ${report.tests.length} / ${report.tests.length} checks matched their expected results.`);
  return assertPublishableLines(fit(lines));
}
