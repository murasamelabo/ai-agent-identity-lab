[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Doctor', 'Keycloak', 'Federated', 'Report')]
    [string]$Action = 'Keycloak',
    [string]$Python,
    [string]$OutputDirectory,
    [ValidateRange(30, 1800)][int]$TimeoutSeconds = 600
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\screenshots'
}
if ($env:OS -ne 'Windows_NT') {
    throw 'Native console capture requires Windows.'
}
if (-not [Environment]::UserInteractive) {
    throw 'An interactive Windows desktop is required; no synthetic terminal image is substituted.'
}
if (-not $PSCmdlet.ShouldProcess($OutputDirectory, "Execute $Action in a new native console and capture its real pixels")) {
    return
}
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class TerminalCaptureNative {
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out Rect r);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int w, int hgt, uint flags);
}
'@
$root = Split-Path -Parent $PSScriptRoot
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('identity-terminal-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporary
$completion = Join-Path $temporary 'complete.json'
$title = 'Identity Lab ' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$worker = Join-Path $PSScriptRoot 'terminal-worker.ps1'
$shellPath = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments = @(('"{0}"' -f $shellPath), '-NoLogo', '-NoProfile', '-File', ('"{0}"' -f $worker),
    '-CompletionFile', ('"{0}"' -f $completion), '-Action', $Action, '-ExpectedTitle', ('"{0}"' -f $title))
if ($Python) { $arguments += @('-Python', ('"{0}"' -f $Python)) }
$process = $null
$workerProcess = $null
$workerStarted = $null
try {
    $process = Start-Process -FilePath (Join-Path $env:WINDIR 'System32\conhost.exe') `
        -ArgumentList $arguments -WorkingDirectory $root -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $deadlineExceeded = $false
    while (-not (Test-Path -LiteralPath $completion)) {
        if ($process.HasExited) { throw 'The native console exited before completion.' }
        if ([DateTime]::UtcNow -ge $deadline) { $deadlineExceeded = $true }
        Start-Sleep -Milliseconds 200
    }
    $metadata = Get-Content -LiteralPath $completion -Raw -Encoding UTF8 | ConvertFrom-Json
    $workerInfo = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + [int]$metadata.pid)
    if (-not $workerInfo -or $workerInfo.ParentProcessId -ne $process.Id -or
        $workerInfo.CommandLine -notlike ('*' + $completion + '*')) {
        throw 'Worker is not a verified child of the console started by this invocation.'
    }
    $workerProcess = Get-Process -Id ([int]$metadata.pid) -ErrorAction Stop
    $workerStarted = $workerProcess.StartTime
    if ($deadlineExceeded) {
        throw 'Capture deadline exceeded. The command was allowed to finish its cleanup; no success image was saved.'
    }
    if (-not $metadata.succeeded -or $metadata.action -ne $Action) {
        throw ('The real command did not succeed; no success screenshot was saved. Failure type: ' +
            $metadata.failure_type + '; line=' + $metadata.failure_line + '; kind=' + $metadata.failure_kind)
    }
    $handle = [IntPtr]::new([long]$metadata.hwnd)
    [uint32]$windowOwner = 0
    $null = [TerminalCaptureNative]::GetWindowThreadProcessId($handle, [ref]$windowOwner)
    if ($windowOwner -notin @($process.Id, $workerProcess.Id)) {
        throw 'Console window does not belong to the verified console or its worker.'
    }
    $caption = [Text.StringBuilder]::new(256)
    $null = [TerminalCaptureNative]::GetWindowText($handle, $caption, $caption.Capacity)
    if ($caption.ToString() -ne $title) { throw 'Window title mismatch; refusing to capture another application.' }
    $captureHeight = if ($Action -eq 'Report') { 500 } elseif ($Action -eq 'Doctor') { 350 } else { 600 }
    if (-not [TerminalCaptureNative]::SetWindowPos($handle, [IntPtr]::Zero, 10, 10, 1200, $captureHeight, 4)) {
        throw 'Cannot place the owned console window for capture.'
    }
    Start-Sleep -Milliseconds 500
    $rectangle = New-Object TerminalCaptureNative+Rect
    if (-not [TerminalCaptureNative]::GetWindowRect($handle, [ref]$rectangle)) {
        throw 'Cannot read the owned native console bounds.'
    }
    $width = $rectangle.Right - $rectangle.Left
    $height = $rectangle.Bottom - $rectangle.Top
    if ($width -lt 200 -or $height -lt 200) { throw 'Invalid native console dimensions.' }
    $image = New-Object Drawing.Bitmap($width, $height)
    $graphics = [Drawing.Graphics]::FromImage($image)
    try {
        $dc = $graphics.GetHdc()
        try {
            if (-not [TerminalCaptureNative]::PrintWindow($handle, $dc, 2)) {
                throw 'Native window capture failed; no rendered transcript fallback is used.'
            }
        } finally { $graphics.ReleaseHdc($dc) }
        $ink = 0
        $paper = 0
        for ($y = 40; $y -lt $height - 40; $y += 3) {
            for ($x = 20; $x -lt $width - 30; $x += 3) {
                $pixel = $image.GetPixel($x, $y)
                if ($pixel.GetBrightness() -lt 0.35) { $ink++ }
                if ($pixel.GetBrightness() -gt 0.75) { $paper++ }
            }
        }
        if ($ink -lt 100 -or $paper -lt 1000) {
            throw 'Native console capture is blank or unusable; no screenshot saved.'
        }
        if (-not (Test-Path -LiteralPath $OutputDirectory)) {
            $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
        }
        $output = Join-Path $OutputDirectory ('terminal-' + $Action.ToLowerInvariant() + '.png')
        $image.Save($output, [Drawing.Imaging.ImageFormat]::Png)
        Write-Output ('Captured actual native terminal: ' + $output)
    } finally {
        $graphics.Dispose()
        $image.Dispose()
    }
} finally {
    if ($workerProcess -and -not $workerProcess.HasExited -and $workerProcess.StartTime -eq $workerStarted) {
        Stop-Process -Id $workerProcess.Id -ErrorAction SilentlyContinue
    } elseif ($process -and -not $process.HasExited) {
        $children = @(Get-CimInstance Win32_Process -Filter ('ParentProcessId = ' + $process.Id) |
            Where-Object { $_.Name -in @('powershell.exe', 'pwsh.exe') -and $_.CommandLine -like ('*' + $completion + '*') })
        foreach ($child in $children) { Stop-Process -Id $child.ProcessId -ErrorAction SilentlyContinue }
    }
    if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $completion) { Remove-Item -LiteralPath $completion -Force }
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
}
