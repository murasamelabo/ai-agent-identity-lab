[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CompletionFile,
    [ValidateSet('Doctor', 'Keycloak', 'FederatedPrepare', 'FederatedRun', 'Federated',
        'EntraPrepare', 'EntraRun', 'EntraAuthz', 'Report',
        'TokenEncoded', 'TokenHeader', 'TokenPayload')][string]$Action,
    [string]$Python,
    [ValidateSet('app_only', 'direct', 'obo', 'agent_input', 'metadata',
        'api_a_input', 'api_b_direct', 'api_b_app_only', 'api_b_obo', 'api_b_metadata',
        'idjag', 'keycloak_access_token')]
    [string]$TokenName = 'obo',
    [Parameter(Mandatory = $true)][string]$ExpectedTitle
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class OwnConsole {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct Font {
        public uint Size; public uint Index; public short X, Y; public int Family, Weight;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string Face;
    }
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int kind);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    public static extern bool SetCurrentConsoleFontEx(IntPtr handle, bool maximum, ref Font font);
}
'@
$font = New-Object OwnConsole+Font
$font.Size = [Runtime.InteropServices.Marshal]::SizeOf($font)
$font.Y = 12
$font.Weight = 400
$font.Face = 'Consolas'
$null = [OwnConsole]::SetCurrentConsoleFontEx([OwnConsole]::GetStdHandle(-11), $false, [ref]$font)
$Host.UI.RawUI.WindowTitle = $ExpectedTitle
$Host.UI.RawUI.BackgroundColor = 'White'
$Host.UI.RawUI.ForegroundColor = 'Black'
try {
    $size = $Host.UI.RawUI.WindowSize
    $size.Width = 140
    $size.Height = if ($Action -eq 'TokenPayload') { 40 } else { 34 }
    $buffer = $Host.UI.RawUI.BufferSize
    $buffer.Width = [Math]::Max($buffer.Width, $size.Width)
    $buffer.Height = [Math]::Max($buffer.Height, 300)
    $Host.UI.RawUI.BufferSize = $buffer
    $Host.UI.RawUI.WindowSize = $size
} catch {
    Write-Warning 'Console size could not be set; capture will use the actual window bounds.'
}
Clear-Host
Write-Output 'AI Agent Identity Lab - actual PowerShell execution'
$command = 'PS> .\scripts\lab.ps1 -Action ' + $Action
if ($Action -like 'Token*') { $command += ' -TokenName ' + $TokenName }
Write-Output $command
Write-Output ''
$success = $false
$failure = ''
$failureLine = 0
$failureKind = ''
try {
    $arguments = @{ Action = $Action; Screen = $true; ErrorAction = 'Stop' }
    if ($Python) { $arguments.Python = $Python }
    if ($Action -like 'Token*') { $arguments.TokenName = $TokenName }
    $output = @(& (Join-Path $PSScriptRoot 'lab.ps1') @arguments 2>&1)
    $allowed = @(
        '^$', '^v?\d+\.\d+\.\d+$', '^Azure CLI session: Enabled; userType=(user|servicePrincipal)$',
        '^Doctor checked local tools/session only\. It does not prove Entra app-management or consent permissions\.$',
        '^Azure CLI not installed: Keycloak-only experiment is available; Entra experiments are not\.$',
        '^Azure CLI session unavailable: Keycloak-only use is available; Entra requires an authorized login\.$',
        '^Executing real (Keycloak|Federated|FederatedPrepare|FederatedRun) experiment\. Raw diagnostics stay private\.$',
        '^COMPLETED FEDERATED EXPERIMENT: CONFIGURATION USED IN THIS RUN$',
        '^Component\s+Endpoint / Identifier\s+Configuration verified$',
        '^\[(ENTRA_IDP|CUSTOM_ISSUER|KEYCLOAK_RCV|USER_LINK|MCP_CLIENT|MCP_SERVER)\]\s+(\<ENTRA_TENANT_ISSUER\>|http://127\.0\.0\.1:(18080/realms/idjag-receiver-lab|\d{2,5}(/mcp)?)|\[MAPPED_ENTRA_USER\] -\> synthetic-reader|mcp-ema-client)\s+(Sign-in IdP \(input token verified\)|Issues oauth-id-jag\+jwt \(RFC 8693\)|Trusts custom-idjag-issuer RSA key|Federated identity linked in Keycloak|JWT authorization grant enabled|Protected resource \(scope: mcp\.read\))$',
        '^FederatedPrepare completed: receiver realm, issuer trust, user link, and MCP server were configured and verified; owned services are now closed\.$',
        '^Actual process output \((known test names only|selected known checks)\):$', '^PASS [a-z][a-z0-9_]{1,120}$',
        '^Verified current run: \d+ / \d+ checks\.$',
        '^Owned container removed; temporary services closed\.$',
        '^CUSTOM broker prototype, not native Entra ID-JAG or stable EMA conformance\.$',
        '^Execution completed; owned local services were closed\.$', '^[{}]$',
        '^\s*"(privacy|evidence_consistency|local_run_integrity|remote_attestation)": (true|false),?$',
        '^REGISTERED ENTRA OBJECTS \(tenant=[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}; prefix=shoten21-obo-[0-9a-f]{8,32}\)$',
        '^Alias\s+Object\s+AppId \(client_id / aud / azp\)\s+ObjectId \(app id / sp oid / user oid\)$',
        '^\[(AI_AGENT_APP|AI_AGENT_SP|BACKEND_API|FRONTEND_CLI|API_A|API_A_SP|API_B|AZURE_CLI)\]\s+(AI-Agent-App \(App reg\)|AI-Agent-App \(Enterprise SP\)|Backend-API \(App reg\)|ai-agent-app \(App reg\)|ai-agent-app \(Enterprise SP\)|backend-api \(App reg\)|Frontend App \(Azure CLI\)|api-a \(App reg\)|api-a \(Enterprise SP\)|api-b \(App reg\)|Azure CLI)\s+[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\s+[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$',
        '^\[USER_A\]\s+Signed-in user\s+\(delegated user subject\)\s+[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$',
        '^EntraPrepare completed: 2 app registrations, service principals, scopes, app role, and consents are ready\.$',
        '^REAL ENTRA TOKEN COMPARISON \((identifiers masked|verified RS256 JWT claims)\)$',
        '^Token\s+audience( \(aud\))?\s+caller( \(azp\))?\s+subject( \(oid\))?\s+permissions$',
        '^(app_only|api_b_app_only)\s+([0-9a-f]{8}-\.\.\. )?\[(BACKEND_API|API_B)\]\s+([0-9a-f]{8}-\.\.\. )?\[(AI_AGENT_APP|API_A)\]\s+([0-9a-f]{8}-\.\.\. )?\[(AI_AGENT_SP|API_A_SP)\]\s+Docs\.Read\.All$',
        '^(direct|api_b_direct)\s+([0-9a-f]{8}-\.\.\. )?\[(BACKEND_API|API_B)\]\s+([0-9a-f]{8}-\.\.\. )?\[(FRONTEND_CLI|AZURE_CLI)\]\s+([0-9a-f]{8}-\.\.\. )?\[USER_A\]\s+Docs\.Metadata Docs\.Read$',
        '^(obo|api_b_obo)\s+([0-9a-f]{8}-\.\.\. )?\[(BACKEND_API|API_B)\]\s+([0-9a-f]{8}-\.\.\. )?\[(AI_AGENT_APP|API_A)\]\s+([0-9a-f]{8}-\.\.\. )?\[USER_A\]\s+Docs\.Read$',
        '^EntraRun completed: 3 Backend API tokens acquired and verified\.$',
        '^REAL ENTRA TOKEN AUTHORIZATION CHECKS \(local Backend API harness\)$',
        '^Case\s+Token\s+Target / Route\s+Decision\s+Result$',
        '^(direct_alice|direct_bob|obo_alice|obo_bob|app_only_alice|app_only_bob|api_b_direct_alice|api_b_direct_bob|api_b_obo_alice|api_b_obo_bob|api_b_app_only_alice|api_b_app_only_bob|app_only_cannot_impersonate_owner|obo_read_token_missing_metadata_route_scope|agent_token_rejected_by_backend_api|api_a_token_rejected_by_api_b)\s+(direct|obo|app_only|agent_input|api_b_direct|api_b_obo|api_b_app_only|api_a_input)\s+(alice \(Docs\.Read\)|bob \(Docs\.Read\)|alice \(App route\)|bob \(App route\)|alice \(User route\)|Docs\.Metadata route|Backend API)\s+(allow|wrong_owner|missing_scope|rejected_wrong_audience)\s+PASS$',
        '^Authorization checks: 9 / 9 matched their expected results\.$',
        '^Real signed Entra tokens; document checks run locally, not an Azure-hosted API\.$',
        '^VERIFIED ENTRA JWT - (ENCODED|HEADER|PAYLOAD) \(publication-redacted\)$',
        '^VERIFIED KEYCLOAK LAB JWT - (ENCODED|HEADER|PAYLOAD) \(publication-redacted\)$',
        '^Token: (app_only|direct|obo|agent_input|metadata|api_a_input|api_b_direct|api_b_app_only|api_b_obo|api_b_metadata)$',
        '^Token: (idjag|keycloak_access_token) \(role=(authorization_grant|access_token); header\.typ=(oauth-id-jag\+jwt|JWT)\)$',
        '^Saved sanitized evidence; no token is acquired by this view\.$',
        '^Source verified: RS256 signature, issuer, audience, lifetime\.$',
        '^Direct API Bearer check \(GET /resource\): HTTP (401 invalid_token|200)$',
        '^(eyJ0eXAiOiJKV1Qi|eyJhbGciOiJSUzI1)?\[HEADER_REDACTED\]\.\[PAYLOAD_REDACTED\]\.\[SIGNATURE_REDACTED\]$',
        '^Base64url lengths \(characters\): header=\d{1,5}; payload=\d{1,5}; signature=\d{1,5}$',
        '^Original header prefix only; all remaining JWT content is redacted\.$',
        '^This redacted text is not a usable or verifiable JWT\.$',
        '^(Header|Payload):$',
        '^\s*"(alg|typ)": "(RS256|JWT|at\+jwt|oauth-id-jag\+jwt|Bearer)",?$',
        '^\s*"(kid|x5t|sub|jti)": "\[REDACTED\]",?$',
        '^\s*"sub": "(synthetic-external-user|\[MAPPED_ENTRA_USER\]|\[LINKED_LOCAL_USER\])",?$',
        '^\s*"(iss|aud|azp|oid|tid)": "\[(TENANT_V2_ISSUER|AI_AGENT_APP|BACKEND_API|FRONTEND_CLI|AI_AGENT_SP|BACKEND_SP|API_A|API_B|AZURE_CLI|API_A_SP|API_B_SP|USER_A|TENANT|OTHER_ACTOR)\]",?$',
        '^\s*"iss": "https://login\.microsoftonline\.com/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}/v2\.0",?$',
        '^\s*"(aud|azp|oid|tid)": "[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",?$',
        '^Directory objects: aud=[0-9a-f]{8}-\.\.\. \[(BACKEND_API|AI_AGENT_APP|API_A|API_B)\]; azp=[0-9a-f]{8}-\.\.\. \[(AI_AGENT_APP|FRONTEND_CLI|API_A|AZURE_CLI)\]; oid=[0-9a-f]{8}-\.\.\. \[(USER_A|AI_AGENT_SP|API_A_SP)\]$',
        '^\s*"iss": "http://127\.0\.0\.1:(18080/(custom-issuer|realms/idjag-receiver-lab)|\d{2,5})",?$',
        '^\s*"aud": "http://127\.0\.0\.1:(18080/realms/idjag-receiver-lab|\d{2,5}/mcp)",?$',
        '^\s*"aud": \[$', '^\s*"(lab-api|account|http://127\.0\.0\.1:\d{2,5}/mcp)",?$',
        '^\s*"(client_id|azp)": "(receiver-client|mcp-ema-client)",?$',
        '^\s*"resource": "(lab-api|http://127\.0\.0\.1:\d{2,5}/mcp)",?$',
        '^\s*"scope": "(lab\.read( profile email)?|email lab\.read profile|mcp\.read( profile email)?|email mcp\.read profile)",?$',
        '^\s*"ver": "2\.0",?$',
        '^\s*"(iat|nbf|exp)": \d{1,12},?$',
        '^\s*"scp": "(?:(access_as_user|Docs\.Read|Docs\.Metadata)( (access_as_user|Docs\.Read|Docs\.Metadata)){0,2})?",?$',
        '^\s*"roles": \[$', '^\s*"Docs\.Read\.All"$', '^\s*\],?$',
        '^\s*"roles": \[\],?$',
        '^Selected original fields only; identity values are redacted\.$',
        '^Omitted fields are not evidence of absence in the original JWT\.$',
        '^Decoding alone is not signature validation\.$'
    )
    foreach ($entry in $output) {
        if (-not ($allowed | Where-Object { [string]$entry -cmatch $_ })) {
            $failureKind = if ([string]$entry -match '^Error in sitecustomize') {
                'EmbeddedPythonSiteWarning'
            } elseif ([string]$entry -match '^Error') {
                'NativeErrorLine'
            } elseif ([string]$entry -match '^Execution') {
                'ExecutionMessage'
            } elseif ([string]$entry -match 'Could not find platform independent libraries') {
                'EmbeddedPythonPrefixWarning'
            } else {
                'UnexpectedOutput(length=' + ([string]$entry).Length + ',type=' +
                $entry.GetType().Name + ',first=' + [int]([string]$entry)[0] + ')'
            }
            throw [InvalidOperationException]::new('PublicationOutputNotAllowlisted')
        }
    }
    $output | ForEach-Object { Write-Output ([string]$_) }
    $success = $true
} catch {
    $failure = $_.Exception.GetType().Name
    $failureLine = $_.InvocationInfo.ScriptLineNumber
    foreach ($kind in @('SyntaxError', 'ModuleNotFoundError', 'AssertionError', 'ImportError',
        'PermissionError', 'FileNotFoundError', 'UnicodeEncodeError')) {
        if ($_.Exception.Message -match $kind) { $failureKind = $kind }
    }
    Write-Output 'EXECUTION FAILED. Screenshot is not successful experiment evidence.'
}
Write-Output ''
if ($success) { Write-Output ('ACTUAL COMMAND COMPLETED: ' + $Action) }
$origin = $Host.UI.RawUI.WindowPosition
$origin.Y = 0
$Host.UI.RawUI.WindowPosition = $origin
$metadata = @{
    hwnd = [OwnConsole]::GetConsoleWindow().ToInt64()
    pid = $PID
    action = $Action
    succeeded = $success
    failure_type = $failure
    failure_line = $failureLine
    failure_kind = $failureKind
}
[IO.File]::WriteAllText($CompletionFile, ($metadata | ConvertTo-Json -Compress),
    [Text.UTF8Encoding]::new($true))
while ($true) { Start-Sleep -Seconds 1 }
