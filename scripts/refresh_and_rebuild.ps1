$ErrorActionPreference = "Stop"

Write-Host "Refreshing Fabric network (WSL)..." -ForegroundColor Cyan
wsl bash -lc "cd /mnt/c/Users/mbunc/Desktop/secure-share && bash scripts/fabric_refresh.sh"

if ($LASTEXITCODE -ne 0) {
    throw "Fabric refresh failed in WSL."
}

Write-Host "Rebuilding ledger from database (Windows)..." -ForegroundColor Cyan
Push-Location "C:\Users\mbunc\Desktop\secure-share\apps\api"
npm run fabric:rebuild

if ($LASTEXITCODE -ne 0) {
    Pop-Location
    throw "Ledger rebuild failed."
}

Pop-Location
Write-Host "Done." -ForegroundColor Green