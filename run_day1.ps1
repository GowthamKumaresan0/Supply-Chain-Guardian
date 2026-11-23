# Day 1 end-to-end run: rebuild the demo scenario, scan, open the report.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')

if (-not (Test-Path targets\nodegoat-upstream)) {
    git clone --quiet https://github.com/OWASP/NodeGoat.git targets\nodegoat-upstream
}
python scripts\make_scenario.py
python -m guardian scan --target targets\nodegoat-modified --baseline targets\nodegoat-baseline --syft @args
Start-Process output\report.html
