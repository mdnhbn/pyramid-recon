param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$venvPath = Join-Path $PSScriptRoot '.venv'
$venvPython = Join-Path $venvPath 'Scripts\python.exe'
$requirementsPath = Join-Path $PSScriptRoot 'requirements.txt'
$stampPath = Join-Path $venvPath '.local-requirements.sha256'

if (-not (Test-Path -LiteralPath $venvPython)) {
    if (Test-Path -LiteralPath $venvPath) {
        throw 'An unrecognized .venv folder already exists. Review it manually or choose a fresh project folder; the launcher will not overwrite it.'
    }

    $basePython = Get-Command python -ErrorAction SilentlyContinue
    if (-not $basePython) { throw 'Install Python 3.11 or newer and make the python command available, then run start_local.bat again.' }
    $baseVersionOutput = (& $basePython.Source --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $baseVersionOutput -notmatch 'Python\s+(\d+\.\d+)') {
        throw "Could not identify the Python version reported by the python command: $baseVersionOutput"
    }
    $baseVersion = [Version]$Matches[1]
    if ($baseVersion -lt [Version]'3.11') {
        throw "Install Python 3.11 or newer; the python command reported $baseVersionOutput."
    }
    & $basePython.Source -m venv $venvPath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $venvPython)) {
        throw 'Python could not create the local environment. Review the output above and try again.'
    }
}

$pythonVersionOutput = (& $venvPython --version).Trim()
if ($LASTEXITCODE -ne 0 -or $pythonVersionOutput -notmatch 'Python\s+(\d+\.\d+)') {
    throw "Could not identify the Python version in the existing .venv ($pythonVersionOutput). It was left unchanged."
}
$pythonVersion = [Version]$Matches[1]
if ($pythonVersion -lt [Version]'3.11') {
    throw "This project expects Python 3.11 or newer; the existing .venv uses $pythonVersionOutput. It was left unchanged."
}

$requirementsHash = (Get-FileHash -LiteralPath $requirementsPath -Algorithm SHA256).Hash
$installedHash = if (Test-Path -LiteralPath $stampPath) { (Get-Content -Raw -LiteralPath $stampPath).Trim() } else { '' }
if ($requirementsHash -ne $installedHash) {
    & $venvPython -m pip install -r $requirementsPath
    if ($LASTEXITCODE -ne 0) {
        throw 'Local Python dependency installation failed. Review the pip output and run start_local.bat again.'
    }
    Set-Content -LiteralPath $stampPath -Value $requirementsHash -NoNewline
}

$runArgs = @()
if ($NoBrowser) { $runArgs += '--no-browser' }
& $venvPython (Join-Path $PSScriptRoot 'run_local.py') @runArgs
exit $LASTEXITCODE
