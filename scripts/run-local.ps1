$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$activate = Join-Path $repoRoot '.venv\Scripts\Activate.ps1'
if (-not (Test-Path $activate)) {
    throw ".venv not found at $repoRoot\.venv"
}

. $activate
Push-Location $repoRoot
try {
    $dataDir = Join-Path $repoRoot '.venv\local-data'
    $logDir  = Join-Path $dataDir 'logs'
    New-Item -ItemType Directory -Force -Path $dataDir, $logDir | Out-Null

    $env:XUI_BIN_FOLDER = Join-Path $repoRoot '.venv\bin'
    $env:XUI_DB_FOLDER  = $dataDir
    $env:XUI_LOG_FOLDER = $logDir
    if (-not $env:XUI_PORT) {
        $env:XUI_PORT = '2053'
    }

    if (-not (Test-Path (Join-Path $repoRoot 'internal\web\dist\index.html'))) {
        Write-Host 'Building frontend bundle first...'
        Push-Location 'frontend'
        try {
            npm run build
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        } finally {
            Pop-Location
        }
    }

    Write-Host "Starting omni-panel locally on port $env:XUI_PORT (DB: $env:XUI_DB_FOLDER, Bins: $env:XUI_BIN_FOLDER)"
    go run . @args
} finally {
    Pop-Location
}
