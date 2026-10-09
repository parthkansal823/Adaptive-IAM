param([switch]$Changed, [switch]$Research)
$ErrorActionPreference = 'Stop'
$repoPath = Split-Path -Parent $PSScriptRoot
Push-Location $repoPath
try {
    $pythonPath = Join-Path $repoPath '.venv/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $pythonPath)) { $pythonPath = 'python' }
    $verifyArguments = @('scripts/verify.py')
    if ($Changed) { $verifyArguments += '--changed' }
    & $pythonPath @verifyArguments
    if ($LASTEXITCODE -ne 0) { throw 'Project verification failed.' }
    if ($Research) {
        & $pythonPath scripts/verify_research.py
        if ($LASTEXITCODE -ne 0) { throw 'Research checksum verification failed.' }
    }
}
finally { Pop-Location }

