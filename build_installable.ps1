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
    throw "No working Python interpreter found."
}

& $python -m pip show pyinstaller *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "PyInstaller is not installed. Install it with: $python -m pip install pyinstaller"
    exit 2
}

New-Item -ItemType Directory -Force dist\EDR_System\config,dist\EDR_System\logs,dist\EDR_System\reports,dist\EDR_System\threat_intel | Out-Null
& $python -m PyInstaller --noconfirm --windowed --name EDR_System run_dashboard.py
Copy-Item -Recurse -Force threat_intel\* dist\EDR_System\threat_intel\
Copy-Item -Recurse -Force reports\* dist\EDR_System\reports\ -ErrorAction SilentlyContinue
Copy-Item -Force README.md,AUDIT.md,start_dashboard.ps1 dist\EDR_System\
Write-Host "Installable folder prepared at dist\EDR_System"

