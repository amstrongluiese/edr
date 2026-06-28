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

& $python -m PyInstaller --noconfirm --clean EDR_System.spec
New-Item -ItemType Directory -Force dist\config,dist\logs,dist\reports,dist\threat_intel,dist\rules | Out-Null
Copy-Item -Recurse -Force config\* dist\config\
Copy-Item -Recurse -Force rules\* dist\rules\
Copy-Item -Recurse -Force threat_intel\* dist\threat_intel\
Copy-Item -Recurse -Force reports\* dist\reports\ -ErrorAction SilentlyContinue
Copy-Item -Force README.md,AUDIT.md dist\
Write-Host "Installable EXE prepared at dist\EDR_System.exe"

