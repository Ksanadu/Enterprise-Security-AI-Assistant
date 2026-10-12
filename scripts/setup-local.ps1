# Restore dependencies without changing .env or business data.
[CmdletBinding()]
param([string]$PythonExecutable = $env:ESAA_BASE_PYTHON, [switch]$SkipFrontend)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root 'backend'
$venv = Join-Path $backend '.venv'
$venvPython = Join-Path $venv 'Scripts\python.exe'

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $Executable (exit $LASTEXITCODE)" }
}

if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
    $candidate = Get-Command python -ErrorAction SilentlyContinue
    if ($candidate) { $PythonExecutable = $candidate.Source }
}
if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
    throw 'Supply a Python 3.12 executable with -PythonExecutable or ESAA_BASE_PYTHON.'
}
Invoke-Checked $PythonExecutable @('-c', 'import sys; assert sys.version_info[:2] == (3, 12), "Python 3.12 is required for the verified local setup"; print(sys.version)')

$healthy = $false
if (Test-Path -LiteralPath $venvPython) {
    & $venvPython -c 'import sys; assert sys.version_info[:2] == (3, 12)' 2>$null
    $healthy = $LASTEXITCODE -eq 0
}
if (-not $healthy -and (Test-Path -LiteralPath $venv)) {
    $resolvedBackend = (Resolve-Path -LiteralPath $backend).Path
    $resolvedVenv = (Resolve-Path -LiteralPath $venv).Path
    $backup = Join-Path $resolvedBackend ('.venv-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    if (-not $resolvedVenv.StartsWith($resolvedBackend + '\') -or -not $backup.StartsWith($resolvedBackend + '\')) {
        throw 'Virtualenv backup must remain inside the backend workspace.'
    }
    Move-Item -LiteralPath $resolvedVenv -Destination $backup
    Write-Host "Preserved broken environment at $backup"
}
if (-not $healthy) { Invoke-Checked $PythonExecutable @('-m', 'venv', $venv) }
Invoke-Checked $venvPython @('-m', 'pip', 'install', '-r', (Join-Path $backend 'requirements-dev.txt'))
Invoke-Checked $venvPython @('-m', 'pip', 'check')
if (-not $SkipFrontend) {
    Push-Location (Join-Path $root 'frontend')
    try { Invoke-Checked 'npm.cmd' @('ci', '--no-audit', '--no-fund') }
    finally { Pop-Location }
}
Write-Host 'Local dependencies ready. Next: scripts/check.ps1' -ForegroundColor Green
