[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CompletionFile,
    [ValidateSet('Doctor', 'Keycloak', 'Federated', 'Report',
        'TokenEncoded', 'TokenHeader', 'TokenPayload')][string]$Action,
    [string]$Python,
    [ValidateSet('api_a_input', 'api_b_direct', 'api_b_app_only', 'api_b_obo', 'api_b_metadata')]
    [string]$TokenName = 'api_b_obo',
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
$font.Y = 20
$font.Weight = 400
$font.Face = 'Consolas'
$null = [OwnConsole]::SetCurrentConsoleFontEx([OwnConsole]::GetStdHandle(-11), $false, [ref]$font)
$Host.UI.RawUI.WindowTitle = $ExpectedTitle
$Host.UI.RawUI.BackgroundColor = 'White'
$Host.UI.RawUI.ForegroundColor = 'Black'
try {
    $size = $Host.UI.RawUI.WindowSize
    $size.Width = 140
    $size.Height = 34
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
        '^Executing real (Keycloak|Federated) experiment\. Raw diagnostics stay private\.$',
        '^Actual process output \((known test names only|selected known checks)\):$', '^PASS [a-z][a-z0-9_]{1,120}$',
        '^Verified current run: \d+ / \d+ checks\.$',
        '^Owned container removed; temporary services closed\.$',
        '^CUSTOM broker prototype, not native Entra ID-JAG or stable EMA conformance\.$',
        '^Execution completed; owned local services were closed\.$', '^[{}]$',
        '^\s*"(privacy|evidence_consistency|local_run_integrity|remote_attestation)": (true|false),?$',
        '^REAL ENTRA TOKEN COMPARISON \(identifiers masked\)$',
        '^Token\s+audience\s+caller\s+subject\s+permissions$',
        '^api_b_app_only\s+\[API_B\]\s+\[API_A\]\s+\[API_A_SP\]\s+Docs\.Read\.All$',
        '^api_b_direct\s+\[API_B\]\s+\[AZURE_CLI\]\s+\[USER_A\]\s+Docs\.Metadata Docs\.Read$',
        '^api_b_obo\s+\[API_B\]\s+\[API_A\]\s+\[USER_A\]\s+Docs\.Read$',
        '^Authorization checks: 9 / 9 matched their expected results\.$',
        '^Real signed Entra tokens; document checks run locally, not an Azure-hosted API\.$',
        '^VERIFIED ENTRA JWT - (ENCODED|HEADER|PAYLOAD) \(publication-redacted\)$',
        '^Token: (api_a_input|api_b_direct|api_b_app_only|api_b_obo|api_b_metadata)$',
        '^Saved sanitized evidence; no token is acquired by this view\.$',
        '^Source verified: RS256 signature, issuer, audience, lifetime\.$',
        '^(eyJ0eXAiOiJKV1Qi|eyJhbGciOiJSUzI1)?\[HEADER_REDACTED\]\.\[PAYLOAD_REDACTED\]\.\[SIGNATURE_REDACTED\]$',
        '^Base64url lengths \(characters\): header=\d{1,5}; payload=\d{1,5}; signature=\d{1,5}$',
        '^Original header prefix only; all remaining JWT content is redacted\.$',
        '^This redacted text is not a usable or verifiable JWT\.$',
        '^\s*"(alg|typ)": "(RS256|JWT|at\+jwt)",?$',
        '^\s*"(kid|x5t|sub)": "\[REDACTED\]",?$',
        '^\s*"(iss|aud|azp|oid|tid)": "\[(TENANT_V2_ISSUER|API_A|API_B|AZURE_CLI|API_A_SP|API_B_SP|USER_A|TENANT|OTHER_ACTOR)\]",?$',
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
