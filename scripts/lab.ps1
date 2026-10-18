[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Setup', 'Doctor', 'Test', 'Keycloak', 'EntraProbe', 'EntraRun',
        'EntraResume', 'EntraAudit', 'EntraVerify', 'Federated', 'Cleanup', 'Report')]
    [string]$Action = 'Doctor',

    [string]$Python,

    [switch]$SkipPython,

    [switch]$Screen
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $root '.venv\Scripts\python.exe'

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    Invoke-Private -Executable $Executable -Arguments $Arguments
}

function Invoke-Private {
    param([string]$Executable, [string[]]$Arguments)
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
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $null = $stderr.Result
        if ($process.ExitCode -ne 0) {
            throw 'Command failed. Native diagnostics were suppressed to protect identity information.'
        }
        $stdout.Result.TrimEnd("`r", "`n") -split '\r?\n'
    } finally { $process.Dispose() }
}

function Get-LabPython {
    if ($Python) {
        $candidate = (Get-Command $Python -ErrorAction Stop).Source
    } else {
        $candidate = $venvPython
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw 'Run Setup first, or supply -Python with an existing compatible Python executable.'
    }
    $null = Invoke-Private -Executable $candidate -Arguments @('-c', 'import sys,jwt,cryptography; assert sys.version_info >= (3,11); assert jwt.__version__ == str(2)+chr(46)+str(13)+chr(46)+str(0); assert cryptography.__version__ == str(46)+chr(46)+str(0)+chr(46)+str(7)')
    return $candidate
}

function Write-Result {
    $report = Join-Path $root 'entra\reports\comparison.json'
    if (-not (Test-Path -LiteralPath $report -PathType Leaf)) {
        throw 'No reader Entra report exists. Historical author examples are not current results.'
    }
    $data = Get-Content -LiteralPath $report -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($data.mode -ne 'real-entra' -or $data.status -ne 'succeeded' -or $data.proof_status -ne 'complete') {
        throw 'Entra result is not complete. Inspect the sanitized blocker output.'
    }
    Write-Output 'REAL ENTRA TOKEN COMPARISON (identifiers masked)'
    Write-Output 'Token                 audience   caller       subject      permissions'
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
        $permissions = (@($token.scp) + @($token.roles)) -join ' '
        Write-Output ('{0,-21} {1,-10} {2,-12} {3,-12} {4}' -f $name, $token.aud, $token.azp, $token.oid, $permissions)
    }
    $cases = @($data.experiments)
    if ($cases.Count -ne 9 -or @($cases | Where-Object { -not $_.passed -or $_.actual -ne $_.expected }).Count) {
        throw 'Authorization checks are incomplete; screenshot output refused.'
    }
    Write-Output 'Authorization checks: 9 / 9 matched their expected results.'
    Write-Output 'Real signed Entra tokens; document checks run locally, not an Azure-hosted API.'
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
        { $_ -in @('Keycloak', 'Federated') } {
            $arguments = @((Join-Path $PSScriptRoot 'public-run.mjs'), $Action)
            if ($Screen) { $arguments += '--brief' }
            Invoke-Checked -Executable 'node' -Arguments $arguments
            Write-Output 'Execution completed; owned local services were closed.'
        }
        default {
            $commands = @{
                EntraProbe = 'probe'; EntraRun = 'run'; EntraResume = 'resume'
                EntraAudit = 'audit'; EntraVerify = 'verify-report'; Cleanup = 'cleanup'
                Report = 'verify-report'
            }
            $runtime = Get-LabPython
            Push-Location -LiteralPath (Join-Path $root 'entra')
            try { Invoke-Checked -Executable $runtime -Arguments @('-X', 'utf8', '-B', 'lab.py', $commands[$Action]) }
            finally { Pop-Location }
            if ($Screen -or $Action -eq 'Report') { Write-Result }
        }
    }
} finally {
    Pop-Location
}
