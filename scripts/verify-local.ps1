$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$activate = Join-Path $repoRoot '.venv\Scripts\Activate.ps1'
if (-not (Test-Path $activate)) {
    throw ".venv not found at $repoRoot\.venv"
}

. $activate
Push-Location $repoRoot
try {
    Write-Host '=== Toolchain Versions (.venv) ==='
    go version
    node -v
    npm -v
    gcc --version | Select-Object -First 1
    golangci-lint --version
    xray version | Select-Object -First 2
    sing-box version | Select-Object -First 2

    Write-Host '=== 1/6 Codegen (openapigen + openapi.json) ==='
    Push-Location 'frontend'
    try {
        npm run gen
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        Write-Host '=== 2/6 Frontend Lint, Format, Typecheck ==='
        npm run lint
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        npm run format:check
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        npm run typecheck
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        Write-Host '=== 3/6 Frontend Tests (Vitest + Storybook Chromium) ==='
        npm test
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        Write-Host '=== 4/6 Frontend Production Build ==='
        npm run build
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }

    Write-Host '=== 5/6 Go Lint + Go Tests ==='
    golangci-lint run
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $goPkgs = go list ./... | Where-Object { $_ -notmatch '/frontend/node_modules/' }
    go test -shuffle=on -count=1 @goPkgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host '=== 6/6 Go Binary Build ==='
    go build -o '.venv\bin\omni-panel.exe' .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host '=== Local verification succeeded ==='
} finally {
    Pop-Location
}
