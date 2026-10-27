[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Setup', 'Doctor', 'Test', 'Keycloak', 'EntraProbe', 'EntraPrepare',
        'EntraRun', 'EntraAuthz', 'EntraResume', 'EntraAudit', 'EntraVerify',
        'FederatedPrepare', 'FederatedRun', 'Federated', 'Cleanup', 'Report',
        'TokenEncoded', 'TokenHeader', 'TokenPayload')]
    [string]$Action = 'Doctor',

    [string]$Python,

    [switch]$SkipPython,

    [switch]$Screen,

    [ValidateSet('app_only', 'direct', 'obo', 'agent_input', 'metadata',
        'api_a_input', 'api_b_direct', 'api_b_app_only', 'api_b_client_credentials',
        'api_b_obo', 'api_b_metadata', 'idjag', 'keycloak_access_token')]
    [string]$TokenName = 'obo',

    [switch]$ShowRawTokens
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $root '.venv\Scripts\python.exe'
$azCliPython = 'C:\Program Files\Microsoft SDKs\Azure\CLI2\python.exe'
if ($ShowRawTokens -and ($Screen -or $Action -notin @('EntraRun', 'EntraResume') -or
        [Console]::IsOutputRedirected)) {
    throw 'Raw tokens require EntraRun/EntraResume in an unredirected local console, never Screen.'
}
if ($PSBoundParameters.ContainsKey('TokenName') -and $Action -notlike 'Token*') {
    throw 'TokenName is supported only for TokenEncoded, TokenHeader and TokenPayload.'
}
$tokenAliasMap = @{
    app_only = 'api_b_app_only'
    api_b_client_credentials = 'api_b_app_only'
    direct = 'api_b_direct'
    obo = 'api_b_obo'
    agent_input = 'api_a_input'
    metadata = 'api_b_metadata'
}
if ($tokenAliasMap.ContainsKey($TokenName)) {
    $TokenName = $tokenAliasMap[$TokenName]
}

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    Invoke-Private -Executable $Executable -Arguments $Arguments
}

function Invoke-Private {
    param([string]$Executable, [string[]]$Arguments, [switch]$RawTokenOutput)
    $command = (Get-Command $Executable -ErrorAction Stop).Source
    $info = New-Object Diagnostics.ProcessStartInfo
    $quoted = @($Arguments | ForEach-Object {
        '"' + ([regex]::Replace(([regex]::Replace($_, '(\\*)"', '$1$1\"')), '(\\+)$', '$1$1')) + '"'
    })
    if ([IO.Path]::GetExtension($command) -eq '.cmd') {
        $info.FileName = $env:ComSpec
        $info.Arguments = '/d /s /c ""' + $command + '" ' + ($quoted -join ' ') + '"'
    } elseif ([IO.Path]::GetExtension($command) -eq '.ps1') {
        $info.FileName = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $info.Arguments = '-NoProfile -File "' + $command + '" ' + ($quoted -join ' ')
    } else {
        $info.FileName = $command
        $info.Arguments = $quoted -join ' '
    }
    $info.WorkingDirectory = (Get-Location).Path
    $info.UseShellExecute = $false
    $info.CreateNoWindow = -not $RawTokenOutput
    $info.RedirectStandardOutput = -not $RawTokenOutput
    $info.RedirectStandardError = $true
    if (-not $RawTokenOutput) {
        $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    }
    $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        $null = $process.Start()
        $stdout = if (-not $RawTokenOutput) { $process.StandardOutput.ReadToEndAsync() }
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $null = $stderr.Result
        if ($process.ExitCode -ne 0) {
            throw 'Command failed. Native diagnostics were suppressed to protect identity information.'
        }
        if (-not $RawTokenOutput) { $stdout.Result.TrimEnd("`r", "`n") -split '\r?\n' }
    } finally { $process.Dispose() }
}

function Get-LabPython {
    if ($Python) {
        $candidate = (Get-Command $Python -ErrorAction Stop).Source
    } elseif (Test-Path -LiteralPath $venvPython -PathType Leaf) {
        $candidate = $venvPython
    } elseif (Test-Path -LiteralPath $azCliPython -PathType Leaf) {
        $candidate = $azCliPython
    } else {
        $candidate = $venvPython
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw 'Run Setup first, or supply -Python with an existing compatible Python executable.'
    }
    $null = Invoke-Private -Executable $candidate -Arguments @('-c', 'import sys,jwt,cryptography; assert sys.version_info >= (3,11); assert jwt.__version__ == str(2)+chr(46)+str(13)+chr(46)+str(0); assert tuple(map(int, cryptography.__version__.split(chr(46))[:3])) >= (46,0,7)')
    return $candidate
}

function Get-EntraStateAndReport {
    param([switch]$AllowProvisionedOnly)
    $report = Join-Path $root 'entra\reports\comparison.json'
    if (-not (Test-Path -LiteralPath $report -PathType Leaf)) {
        throw 'No reader Entra report exists. Historical author examples are not current results.'
    }
    $data = Get-Content -LiteralPath $report -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($AllowProvisionedOnly) {
        if ($data.mode -ne 'real-entra' -or $data.status -notin @('provisioned', 'succeeded')) {
            throw 'Entra preparation is not complete. Inspect the sanitized blocker output.'
        }
    } else {
        if ($data.mode -ne 'real-entra' -or $data.status -ne 'succeeded' -or $data.proof_status -ne 'complete') {
            throw 'Entra result is not complete. Inspect the sanitized blocker output.'
        }
    }
    $stateRoot = Join-Path $env:LOCALAPPDATA 'Shoten21IdentityLab'
    $latestFile = Join-Path $stateRoot 'latest.json'
    $runId = if (Test-Path -LiteralPath $latestFile -PathType Leaf) {
        (Get-Content -LiteralPath $latestFile -Raw -Encoding UTF8 | ConvertFrom-Json).run
    } else {
        (Get-Content -LiteralPath (Join-Path $stateRoot 'latest.txt') -Raw -Encoding UTF8).Trim()
    }
    $state = Get-Content -LiteralPath (Join-Path (Join-Path $stateRoot $runId) 'state.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    return @{ Report = $data; State = $state }
}

function Write-EntraPreparedObjects {
    $ctx = Get-EntraStateAndReport -AllowProvisionedOnly
    $state = $ctx.State
    $cliAppId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    Write-Output ('REGISTERED ENTRA OBJECTS (tenant=' + $state.tenant + '; prefix=' + $state.prefix + ')')
    Write-Output 'Alias            Object                        AppId (client_id / aud / azp)         ObjectId (app id / sp oid / user oid)'
    Write-Output ('{0,-16} {1,-29} {2,-37} {3}' -f '[AI_AGENT_APP]', 'AI-Agent-App (App reg)', $state.apps.a.appId, $state.apps.a.id)
    Write-Output ('{0,-16} {1,-29} {2,-37} {3}' -f '[AI_AGENT_SP]', 'AI-Agent-App (Enterprise SP)', $state.apps.a.appId, $state.apps.a.spId)
    Write-Output ('{0,-16} {1,-29} {2,-37} {3}' -f '[BACKEND_API]', 'Backend-API (App reg)', $state.apps.b.appId, $state.apps.b.id)
    Write-Output ('{0,-16} {1,-29} {2,-37} {3}' -f '[FRONTEND_CLI]', 'Frontend App (Azure CLI)', $cliAppId, $state.cliSpId)
    Write-Output ('{0,-16} {1,-29} {2,-37} {3}' -f '[USER_A]', 'Signed-in user', '(delegated user subject)', $state.user)
    Write-Output ''
    Write-Output 'EntraPrepare completed: 2 app registrations, service principals, scopes, app role, and consents are ready.'
}

function Write-EntraTokenComparison {
    $ctx = Get-EntraStateAndReport
    $data = $ctx.Report
    $state = $ctx.State
    $cliAppId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    Write-Output 'REAL ENTRA TOKEN COMPARISON (verified RS256 JWT claims)'
    Write-Output 'Token          audience (aud)               caller (azp)                 subject (oid)                permissions'
    $guidMap = @{
        '[API_A]' = $state.apps.a.appId
        '[API_B]' = $state.apps.b.appId
        '[AZURE_CLI]' = $cliAppId
        '[API_A_SP]' = $state.apps.a.spId
        '[USER_A]' = $state.user
    }
    $aliasDisplay = @{
        '[API_A]' = '[AI_AGENT_APP]'
        '[API_B]' = '[BACKEND_API]'
        '[AZURE_CLI]' = '[FRONTEND_CLI]'
        '[API_A_SP]' = '[AI_AGENT_SP]'
        '[USER_A]' = '[USER_A]'
    }
    $tokenDisplay = @{
        api_b_app_only = 'app_only'
        api_b_direct = 'direct'
        api_b_obo = 'obo'
    }
    $expected = @{
        api_b_app_only = @('[API_B]', '[API_A]', '[API_A_SP]', '', 'Docs.Read.All')
        api_b_direct = @('[API_B]', '[AZURE_CLI]', '[USER_A]', 'Docs.Metadata Docs.Read', '')
        api_b_obo = @('[API_B]', '[API_A]', '[USER_A]', 'Docs.Read', '')
    }
    foreach ($name in @('api_b_app_only', 'api_b_direct', 'api_b_obo')) {
        $token = $data.tokens.$name
        $values = @($token.aud, $token.azp, $token.oid, ($token.scp -join ' '), ($token.roles -join ' '))
        if ($token.signature_issuer_audience_lifetime -ne 'verified' -or
            ($values -join '|') -ne ($expected[$name] -join '|')) {
            throw 'Unexpected or unmasked token context; screenshot output refused.'
        }
        $audCell = ($guidMap[$token.aud].Substring(0, 8) + '-... ' + $aliasDisplay[$token.aud])
        $azpCell = ($guidMap[$token.azp].Substring(0, 8) + '-... ' + $aliasDisplay[$token.azp])
        $oidCell = ($guidMap[$token.oid].Substring(0, 8) + '-... ' + $aliasDisplay[$token.oid])
        $permissions = (@($token.scp) + @($token.roles)) -join ' '
        Write-Output ('{0,-14} {1,-28} {2,-28} {3,-28} {4}' -f $tokenDisplay[$name], $audCell, $azpCell, $oidCell, $permissions)
    }
    $cases = @($data.experiments)
    if ($cases.Count -ne 9 -or @($cases | Where-Object { -not $_.passed -or $_.actual -ne $_.expected }).Count) {
        throw 'Authorization checks are incomplete; screenshot output refused.'
    }
    Write-Output ''
    Write-Output 'EntraRun completed: 3 Backend API tokens acquired and verified.'
}

function Write-EntraAuthzChecks {
    $ctx = Get-EntraStateAndReport
    $data = $ctx.Report
    $cases = @($data.experiments)
    if ($cases.Count -ne 9 -or @($cases | Where-Object { -not $_.passed -or $_.actual -ne $_.expected }).Count) {
        throw 'Authorization checks are incomplete; screenshot output refused.'
    }
    $meta = @{
        api_b_direct_alice = @('direct_alice', 'direct', 'alice (Docs.Read)')
        api_b_direct_bob = @('direct_bob', 'direct', 'bob (Docs.Read)')
        api_b_obo_alice = @('obo_alice', 'obo', 'alice (Docs.Read)')
        api_b_obo_bob = @('obo_bob', 'obo', 'bob (Docs.Read)')
        api_b_app_only_alice = @('app_only_alice', 'app_only', 'alice (App route)')
        api_b_app_only_bob = @('app_only_bob', 'app_only', 'bob (App route)')
        app_only_cannot_impersonate_owner = @('app_only_cannot_impersonate_owner', 'app_only', 'alice (User route)')
        obo_read_token_missing_metadata_route_scope = @('obo_read_token_missing_metadata_route_scope', 'obo', 'Docs.Metadata route')
        api_a_token_rejected_by_api_b = @('agent_token_rejected_by_backend_api', 'agent_input', 'Backend API')
    }
    Write-Output 'REAL ENTRA TOKEN AUTHORIZATION CHECKS (local Backend API harness)'
    Write-Output 'Case                                         Token        Target / Route      Decision                 Result'
    foreach ($case in $cases) {
        $info = $meta[$case.name]
        if (-not $info) { throw 'Unknown authorization case.' }
        Write-Output ('{0,-44} {1,-12} {2,-19} {3,-24} {4}' -f $info[0], $info[1], $info[2], $case.actual, 'PASS')
    }
    Write-Output ''
    Write-Output 'Authorization checks: 9 / 9 matched their expected results.'
    Write-Output 'Real signed Entra tokens; document checks run locally, not an Azure-hosted API.'
}

function Write-Result {
    Write-EntraPreparedObjects
    Write-Output ''
    Write-EntraTokenComparison
}

if (-not $PSCmdlet.ShouldProcess($Action, 'Run the explicitly selected identity laboratory action')) {
    return
}

Push-Location -LiteralPath $root
try {
    switch ($Action) {
        'Setup' {
            foreach ($tool in @('node', 'docker')) {
                if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
                    throw "Install $tool before running Setup. No global tools are installed automatically."
                }
            }
            $nodeVersion = & node --version
            if ($LASTEXITCODE -ne 0 -or [int]($nodeVersion.TrimStart('v').Split('.')[0]) -lt 22) {
                throw 'Node.js 22 or later is required.'
            }
            Invoke-Checked -Executable 'docker' -Arguments @('version', '--format', '{{.Server.Version}}')
            Invoke-Checked -Executable 'docker' -Arguments @('pull', 'quay.io/keycloak/keycloak:26.8.1@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244')
            if (-not $SkipPython) {
                if ($Python) {
                    $null = Get-LabPython
                    Write-Output 'Using the explicitly supplied existing Python; its installation is unchanged.'
                } else {
                    Invoke-Checked -Executable 'python' -Arguments @('-c', 'import sys; assert sys.version_info >= (3, 11)')
                    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
                        Invoke-Checked -Executable 'python' -Arguments @('-m', 'venv', (Join-Path $root '.venv'))
                    }
                    Invoke-Checked -Executable $venvPython -Arguments @('-m', 'pip', 'install', '-r', (Join-Path $root 'entra\requirements.txt'))
                    $null = Get-LabPython
                }
            }
            Write-Output 'Setup complete. No Azure resources, consent, login or tenant policies were changed.'
        }
        'Doctor' {
            $nodeVersion = & node --version
            if ($LASTEXITCODE -ne 0 -or [int]($nodeVersion.TrimStart('v').Split('.')[0]) -lt 22) {
                throw 'Node.js 22 or later is required.'
            }
            Write-Output $nodeVersion
            Invoke-Checked -Executable 'docker' -Arguments @('version', '--format', '{{.Server.Version}}')
            if (Get-Command az -ErrorAction SilentlyContinue) {
                $sessionAvailable = $false
                $sessionText = ''
                try {
                    $sessionText = (Invoke-Private -Executable 'az' -Arguments @('account', 'show', '--query', '{state:state,userType:user.type}', '--output', 'json', '--only-show-errors')) -join "`n"
                    $sessionAvailable = $true
                } catch {
                    Write-Output 'Azure CLI session unavailable: Keycloak-only use is available; Entra requires an authorized login.'
                }
                if ($sessionAvailable) {
                    $session = $sessionText | ConvertFrom-Json
                    if (-not $session -or $session.state -ne 'Enabled' -or $session.userType -notin @('user', 'servicePrincipal')) {
                        throw 'Azure CLI session is not an enabled supported identity.'
                    }
                    Write-Output ('Azure CLI session: Enabled; userType=' + $session.userType)
                }
            } else {
                Write-Output 'Azure CLI not installed: Keycloak-only experiment is available; Entra experiments are not.'
            }
            Write-Output 'Doctor checked local tools/session only. It does not prove Entra app-management or consent permissions.'
        }
        'Test' {
            Push-Location -LiteralPath (Join-Path $root 'keycloak')
            try {
                Invoke-Checked -Executable 'npm.cmd' -Arguments @('run', 'check', '--silent')
                Invoke-Checked -Executable 'npm.cmd' -Arguments @('run', 'test:unit', '--silent')
            } finally { Pop-Location }
            if (-not $SkipPython) {
                $runtime = Get-LabPython
                Push-Location -LiteralPath (Join-Path $root 'entra')
                try { Invoke-Checked -Executable $runtime -Arguments @('-B', '-m', 'unittest', '-v') }
                finally { Pop-Location }
                Write-Output 'Python offline checks completed successfully (unittest exit 0).'
            }
            Write-Output 'Offline tests passed. This is not proof of an Entra token acquisition.'
        }
        { $_ -in @('Keycloak', 'Federated', 'FederatedPrepare', 'FederatedRun') } {
            $arguments = @((Join-Path $PSScriptRoot 'public-run.mjs'), $Action)
            if ($Screen) { $arguments += '--brief' }
            Invoke-Checked -Executable 'node' -Arguments $arguments
            if ($Action -ne 'FederatedPrepare') {
                Write-Output 'Execution completed; owned local services were closed.'
            }
        }
        default {
            if ($Action -like 'Token*' -and $TokenName -in @('idjag', 'keycloak_access_token')) {
                Invoke-Checked -Executable 'node' -Arguments @(
                    (Join-Path $PSScriptRoot 'public-run.mjs'),
                    'TokenView',
                    $Action.Substring(5).ToLowerInvariant(),
                    $TokenName
                )
                break
            }
            $commands = @{
                EntraProbe = 'probe'; EntraPrepare = 'prepare'; EntraRun = 'run'
                EntraAuthz = 'verify-report'; EntraResume = 'resume'
                EntraAudit = 'audit'; EntraVerify = 'verify-report'; Cleanup = 'cleanup'
                Report = 'verify-report'; TokenEncoded = 'token-view'
                TokenHeader = 'token-view'; TokenPayload = 'token-view'
            }
            $runtime = Get-LabPython
            Push-Location -LiteralPath (Join-Path $root 'entra')
            try {
                $pyCommand = if ($Screen -and $Action -in @('EntraPrepare', 'EntraRun', 'EntraAuthz', 'Report')) {
                    'verify-report'
                } else {
                    $commands[$Action]
                }
                $arguments = @('-X', 'utf8', '-B', 'lab.py', $pyCommand)
                if ($Action -like 'Token*') {
                    $arguments += @('--view', $Action.Substring(5).ToLowerInvariant(),
                        '--token-name', $TokenName)
                }
                if ($ShowRawTokens) { $arguments += '--show-raw-tokens' }
                $pyOut = Invoke-Private -Executable $runtime -Arguments $arguments -RawTokenOutput:$ShowRawTokens
                if ($Action -notin @('EntraPrepare', 'EntraRun', 'EntraAuthz', 'Report') -or $ShowRawTokens) {
                    $pyOut
                }
            }
            finally { Pop-Location }
            if ($Action -eq 'EntraPrepare') { Write-EntraPreparedObjects }
            elseif ($Action -eq 'EntraRun') { Write-EntraTokenComparison }
            elseif ($Action -eq 'EntraAuthz') { Write-EntraAuthzChecks }
            elseif ($Action -eq 'Report') { Write-Result }
        }
    }
} finally {
    Pop-Location
}
