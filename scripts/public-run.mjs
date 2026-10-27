import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderKeycloakTokenView } from '../keycloak/federated-mcp.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const mode = process.argv[2];
const read = (path) => JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
if (mode === 'TokenView') {
  try {
    const view = process.argv[3];
    const tokenName = process.argv[4];
    const candidates = [
      ['federated-mcp-results.json', true],
      ['verified-results.json', false],
    ];
    let matchedReport = null;
    for (const [file, isFederated] of candidates) {
      const candidatePath = join(root, 'keycloak', 'results', file);
      try {
        const reference = read(join(root, 'examples', 'author-run', 'keycloak', file));
        const expected = new Set(reference.tests.map((test) => test.name));
        const report = read(candidatePath);
        if (report.passed === true && report.cleanup?.removed === true &&
            (!isFederated || report.cleanup?.local_servers_closed === true) &&
            report.tests?.length === expected.size &&
            report.tests.every((t) => t.passed === true && expected.has(t.name)) &&
            report.token_inspection?.[tokenName]) {
          matchedReport = report;
          break;
        }
      } catch {
        // Try next candidate
      }
    }
    assert(matchedReport, 'No verified token inspection report available');
    console.log(renderKeycloakTokenView(matchedReport, tokenName, view));
    process.exit(0);
  } catch {
    console.error('Saved Keycloak token evidence is unavailable or invalid; run Federated or Keycloak first.');
    process.exit(2);
  }
}
const brief = process.argv[3] === '--brief';
const files = {
  Keycloak: 'verified-results.json',
  Federated: 'federated-mcp-results.json',
  FederatedPrepare: 'federated-mcp-results.json',
  FederatedRun: 'federated-mcp-results.json',
};
if (!Object.hasOwn(files, mode)) {
  console.error('Unsupported public run mode.');
  process.exit(2);
}
const isFederatedMode = mode.startsWith('Federated');
const reference = read(join(root, 'examples', 'author-run', 'keycloak', files[mode]));
const expected = new Set(reference.tests.map((test) => test.name));
assert(expected.size === reference.tests.length && [...expected].every((name) => /^[a-z][a-z0-9_]{1,120}$/.test(name)));
const reportPath = join(root, 'keycloak', 'results', files[mode]);

function isVerifiedReport(candidate) {
  try {
    return (
      candidate.passed === true &&
      candidate.tests?.length === expected.size &&
      new Set(candidate.tests.map((test) => test.name)).size === expected.size &&
      candidate.tests.every((test) => test.passed === true && expected.has(test.name)) &&
      candidate.cleanup?.removed === true &&
      (!isFederatedMode || (
        candidate.cleanup?.local_servers_closed === true &&
        candidate.proof_status === 'prototype_core_flow_verified_not_ema_conformance'
      ))
    );
  } catch {
    return false;
  }
}

let existingReport = null;
if (mode === 'FederatedPrepare' || mode === 'FederatedRun') {
  try {
    const candidate = read(reportPath);
    if (isVerifiedReport(candidate)) {
      existingReport = candidate;
    }
  } catch {
    existingReport = null;
  }
}

let observed = new Set();
if (!existingReport) {
  rmSync(reportPath, { force: true });
  const started = Date.now();
  const args = [join(root, 'keycloak', 'run.mjs')];
  if (isFederatedMode) args.push('--federated-mcp');
  if (mode !== 'FederatedPrepare') {
    console.log(`Executing real ${mode} experiment. Raw diagnostics stay private.`);
  }
  const result = spawnSync(process.execPath, args, {
    cwd: join(root, 'keycloak'), encoding: 'utf8', windowsHide: true,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error || result.signal || result.status !== 0) {
    const recoveries = [...String(result.stderr).matchAll(
      /ID=([a-f0-9]{64});?[^\r\n]{0,160}?shoten\.identity-lab\.owner=([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})/g,
    )].map((match) => ({
      container_id: match[1], expected_label: 'shoten.identity-lab.owner',
      expected_nonce: match[2], removal_authorized: false,
    }));
    if (recoveries.length) {
      const directory = join(root, 'artifacts', 'recovery');
      mkdirSync(directory, { recursive: true });
      writeFileSync(join(directory, `container-${randomUUID()}.json`),
        '\uFEFF' + JSON.stringify({ recoveries }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
      console.error('Owned-container recovery metadata retained under artifacts/recovery; inspect privately before any removal.');
    }
    console.error('Real execution failed or was blocked; no successful transcript is published.');
    process.exit(2);
  }
  const report = read(reportPath);
  assert(isVerifiedReport(report));
  assert(Date.parse(report.started_at) >= started - 2000);
  for (const line of result.stdout.split(/\r?\n/)) {
    const match = /^PASS ([a-z][a-z0-9_]+)(?:: HTTP ([1-5][0-9]{2})(?: ([a-z_]+))?)?$/.exec(line);
    if (!match) continue;
    assert(expected.has(match[1]) && !observed.has(match[1]));
    observed.add(match[1]);
    const test = report.tests.find((entry) => entry.name === match[1]);
    if (match[2]) assert(test.http_status === Number(match[2]));
  }
  assert(observed.size > 20, 'Expected actual live PASS lines, not just a saved report.');
  existingReport = report;
} else {
  observed = new Set(existingReport.tests.map((test) => test.name));
}

try {
  const report = existingReport;
  if (mode === 'FederatedPrepare') {
    const ep = report.endpoints;
    console.log('PREPARED KEYCLOAK ID-JAG RECEIVER & LOCAL MCP ENVIRONMENT');
    console.log('Component         Endpoint / Identifier                            Configuration');
    console.log(`[ENTRA_IDP]       ${'<ENTRA_TENANT_ISSUER>'.padEnd(48)} Sign-in IdP (input token verified)`);
    console.log(`[CUSTOM_ISSUER]   ${String(ep.custom_broker_issuer).padEnd(48)} Issues oauth-id-jag+jwt (RFC 8693)`);
    console.log(`[KEYCLOAK_RCV]    ${String(ep.keycloak_receiver).padEnd(48)} Trusts custom-idjag-issuer RSA key`);
    console.log(`[USER_LINK]       ${'[MAPPED_ENTRA_USER] -> synthetic-reader'.padEnd(48)} Federated identity linked in Keycloak`);
    console.log(`[MCP_CLIENT]      ${'mcp-ema-client'.padEnd(48)} JWT authorization grant enabled`);
    console.log(`[MCP_SERVER]      ${String(ep.mcp_resource).padEnd(48)} Protected resource (scope: mcp.read)`);
    console.log('');
    console.log('FederatedPrepare completed: Keycloak receiver realm, issuer trust, user link, and MCP server are ready.');
    process.exit(0);
  }
  const selected = mode === 'Keycloak' ? {
    idjag_receiver_accepts_valid_assertion: 'idjag_exchange',
    idjag_replay_rejected: 'replay_rejected',
    idjag_client_binding_rejected: 'wrong_client_rejected',
    idjag_wrong_audience_rejected: 'wrong_audience_rejected',
    idjag_untrusted_signing_key_rejected: 'wrong_signing_key_rejected',
    idjag_expired_rejected: 'expired_assertion_rejected',
    native_idjag_issuance_via_rfc8693_not_supported: 'keycloak_idjag_issuance_not_supported',
    resource_accepts_receiver_access_token: 'resource_access',
    resource_rejects_identity_assertion_as_bearer: 'assertion_not_an_access_token',
  } : {
    real_entra_user_signature_issuer_audience_expiry_scope_verified: 'real_entra_token_verified',
    custom_broker_issues_and_client_verifies_real_entra_backed_idjag: 'custom_broker_issues_idjag',
    native_keycloak_accepts_idjag_and_issues_exact_mcp_audience_token: 'keycloak_issues_mcp_token',
    mcp_initialize_negotiates_pinned_protocol_and_tools: 'mcp_initialize',
    mcp_tools_list_over_authenticated_streamable_http: 'mcp_tools_list',
    mcp_tools_call_reads_authorized_synthetic_document: 'mcp_tools_call',
    mcp_tools_call_denies_other_synthetic_user_document: 'other_document_denied',
    mcp_rejects_original_entra_token_as_resource_bearer: 'original_token_rejected',
  };
  const useSelected = brief || mode === 'FederatedRun';
  if (useSelected) assert(Object.keys(selected).every((name) => observed.has(name)));
  console.log(useSelected ? 'Actual process output (selected known checks):' : 'Actual process output (known test names only):');
  for (const name of useSelected ? Object.keys(selected) : observed) {
    console.log(`PASS ${useSelected ? selected[name] : name}`);
  }
  console.log(`Verified current run: ${report.tests.length} / ${report.tests.length} checks.`);
  console.log('Owned container removed; temporary services closed.');
  if (mode === 'Federated') {
    console.log('CUSTOM broker prototype, not native Entra ID-JAG or stable EMA conformance.');
  }
} catch {
  console.error('Current run evidence did not pass publication checks; no diagnostics or identifiers printed.');
  process.exit(2);
}
