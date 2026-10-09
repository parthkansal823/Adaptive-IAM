param([switch]$SkipFrontend, [switch]$SkipHooks)
$ErrorActionPreference = 'Stop'
$repoPath = Split-Path -Parent $PSScriptRoot
Push-Location $repoPath
try {
    if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) {
        python -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed.' }
    }
    & '.venv/Scripts/python.exe' -m pip install -r backend/requirements-dev.txt
    if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed.' }
    if (-not $SkipFrontend) {
        if (Test-Path -LiteralPath 'frontend/package-lock.json') { npm.cmd --prefix frontend ci }
        else { npm.cmd --prefix frontend install }
        if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
    }
    if (-not $SkipHooks) {
        git config --local core.hooksPath .githooks
        if ($LASTEXITCODE -ne 0) { throw 'Git hooks configuration failed. Run git init first.' }
    }
    Write-Host 'Setup complete. Run npm run dev to start both services.'
    Write-Host 'Project Codex lifecycle hooks require review/trust with /hooks before activation.'
}
finally { Pop-Location }
