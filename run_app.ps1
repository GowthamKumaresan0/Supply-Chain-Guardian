# Start the Supply Chain Guardian web app and open it in the browser.
Set-Location $PSScriptRoot
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
Start-Process "http://127.0.0.1:8765"
python -m guardian serve --port 8765
