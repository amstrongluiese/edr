$ErrorActionPreference = "Stop"

$candidates = @(
    "python",
    "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe",
    "$env:LOCALAPPDATA\Python\bin\python.exe"
)

$python = $null
foreach ($candidate in $candidates) {
    try {
        & $candidate --version *> $null
        if ($LASTEXITCODE -eq 0) {
            $python = $candidate
            break
        }
    } catch {
        continue
    }
}

if (-not $python) {
    throw "No working Python interpreter found. Install Python 3.11+ or update start_dashboard.ps1 with its path."
}

& $python "$PSScriptRoot\run_dashboard.py"

