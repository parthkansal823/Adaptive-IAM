param([ValidateSet('backend','frontend')][string]$Service = 'backend')
$ErrorActionPreference = 'Stop'
$repoPath = Split-Path -Parent $PSScriptRoot
Push-Location $repoPath
try {
    if ($Service -eq 'backend') {
        if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) { throw 'Run scripts/setup.ps1 first.' }
        & '.venv/Scripts/python.exe' -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
    }
    else { npm.cmd --prefix frontend run dev }
    if ($LASTEXITCODE -ne 0) { throw "$Service development server exited with code $LASTEXITCODE." }
}
finally { Pop-Location }

