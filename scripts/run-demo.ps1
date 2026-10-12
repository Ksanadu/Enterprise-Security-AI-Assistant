# Simulated demo in an explicitly owned data directory; -Fresh starts a new
# instance instead of deleting any data. Existing .env and business DB are untouched.
[CmdletBinding()]
param(
    [ValidatePattern('^[a-z0-9][a-z0-9-]{0,48}$')][string]$Instance = 'default',
    [switch]$Fresh,
    [switch]$Check,
    [switch]$DemoCheck,
    [switch]$SimulateModelFailure,
    [int]$FrontendPort = 5180,
    [int]$BackendPort = 8110
)
$ErrorActionPreference = 'Stop'
$demoRoot = [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $PSScriptRoot) 'logs\demo'))
if ($Fresh) { $Instance = 'run-' + [guid]::NewGuid().ToString('N').Substring(0,12) }
$instanceRoot = [System.IO.Path]::GetFullPath((Join-Path $demoRoot $Instance))
if (-not $instanceRoot.StartsWith($demoRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Demo directory escaped its owned root.' }
$marker = Join-Path $instanceRoot 'demo-instance.json'
if (Test-Path -LiteralPath $instanceRoot) {
    if ((Get-Item -LiteralPath $instanceRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Demo directory must not be a link.' }
    if (-not (Test-Path -LiteralPath $marker)) { throw 'Existing directory is not an owned demo instance. Use -Fresh.' }
    $state = Get-Content -Raw -LiteralPath $marker | ConvertFrom-Json
    if ($state.purpose -ne 'ESAA simulated demo' -or $state.instance -ne $Instance) { throw 'Demo ownership marker does not match.' }
} else {
    New-Item -ItemType Directory -Path $instanceRoot | Out-Null
    $keyBytes = New-Object byte[] 48
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($keyBytes)
    $state = @{ purpose='ESAA simulated demo'; instance=$Instance; signing_key=[Convert]::ToBase64String($keyBytes) }
    $state | ConvertTo-Json | Set-Content -LiteralPath $marker -Encoding utf8
}
$projectRoot = Split-Path -Parent $PSScriptRoot
$demoEnvironment = @{
    APP_ENV='development'; DEBUG='false'; AUTH_SECRET_KEY=$state.signing_key
    DATABASE_URL=('sqlite:///' + ((Join-Path $instanceRoot 'app.db') -replace '\\','/'))
    VECTOR_STORE_PATH=(Join-Path $instanceRoot 'index'); KB_DIR=(Join-Path $projectRoot 'backend\knowledge_base')
    LLM_PROVIDER='mock'; LLM_API_KEY=''; LLM_BASE_URL='http://127.0.0.1:1/v1'; LLM_MODEL='synthetic-unavailable-model'
    LLM_TIMEOUT_SECONDS='2'; LLM_MAX_RETRIES='0'; EMBEDDING_PROVIDER='tfidf'; EMBEDDING_API_KEY=''; EMBEDDING_BASE_URL=''
    ALLOW_DEMO_LOGIN='true'; SEED_DEMO_USERS='true'; DEMO_USER_PASSWORD='Demo@12345'
    CHAT_RATE_LIMIT_PER_MINUTE='1000'; WORKFLOW_RETRY_INTERVAL_SECONDS='5'
    NOTIFICATION_WEBHOOK_URL=''; NOTIFICATION_LEAD_WEBHOOK_URL=''; NOTIFICATION_SIGNING_SECRET=''
    NOTIFICATION_CA_BUNDLE_FILE=''; NOTIFICATION_POLL_INTERVAL_SECONDS='0'
    RETENTION_POLICY_FILE=''; RETENTION_BACKUP_DIR=''
}
if ($SimulateModelFailure) { $demoEnvironment.LLM_PROVIDER='openai_compatible'; $demoEnvironment.LLM_API_KEY='synthetic-demo-key' }
$previous = @{}
foreach ($name in $demoEnvironment.Keys) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    foreach ($name in $demoEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $demoEnvironment[$name], 'Process') }
    Write-Host "Simulated demo instance: $Instance" -ForegroundColor Cyan
    Write-Host "Data directory: $instanceRoot"
    Write-Host 'Use -Fresh for an empty new demo instance. No existing data is deleted.'
    if ($SimulateModelFailure) { Write-Host 'Fault mode: configured model endpoint is unreachable; expect offline-fallback answers.' -ForegroundColor Yellow }
    & (Join-Path $PSScriptRoot 'run-local.ps1') -Check:$Check -DemoCheck:$DemoCheck -FrontendPort $FrontendPort -BackendPort $BackendPort -LogDirectory (Join-Path $instanceRoot 'logs')
    $result = $LASTEXITCODE
} finally {
    foreach ($name in $demoEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
}
exit $result
