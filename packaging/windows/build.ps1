# Build dist\v6race.exe. Run on Windows from anywhere; needs Python 3.12+
# (the "py" launcher from python.org). Everything stays in the repository:
# a private build venv and PyInstaller's build/ and dist/ folders.
$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $repo

# Windows PowerShell doesn't stop on a failing native command by itself.
function Invoke-Step([string]$what, [scriptblock]$step) {
    & $step
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" }
}

if (-not (Test-Path .build-venv)) { Invoke-Step 'creating the build venv' { py -3 -m venv .build-venv } }
Invoke-Step 'installing PyInstaller' { .\.build-venv\Scripts\python -m pip install --quiet --upgrade pip pyinstaller }
Remove-Item -Force -ErrorAction SilentlyContinue dist\v6race.exe
Invoke-Step 'PyInstaller' {
    .\.build-venv\Scripts\pyinstaller --noconfirm --clean --onefile --console `
        --name v6race --paths src packaging\windows\entry.py
}
if (-not (Test-Path dist\v6race.exe)) { throw 'dist\v6race.exe was not produced' }
Write-Host "built $repo\dist\v6race.exe"
