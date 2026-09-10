param(
  [switch]$CollectLive,
  [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$vulnerableApp = Join-Path $repoRoot "vulnerable-app"

function Invoke-Checked {
  param(
    [string]$Command,
    [string[]]$Arguments,
    [string]$WorkingDirectory
  )

  & $Command @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed: $Command $($Arguments -join ' ')"
  }
}

Write-Host "Starting SCC dashboard..."
Invoke-Checked "docker" @("compose", "up", "--build", "-d") $repoRoot

Write-Host "Starting vulnerable demo app..."
Invoke-Checked "docker" @("compose", "up", "--build", "-d") $vulnerableApp

Write-Host "Seeding demo CVE..."
Invoke-Checked "npm.cmd" @("run", "seed-demo-cve") $repoRoot

if ($CollectLive) {
  Write-Host "Collecting live CVE and GitHub data..."
  & "npm.cmd" run get-cve
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "Live collection failed; the seeded demo CVE remains available."
  }
}

Write-Host "Checking dashboard..."
$dashboard = Invoke-WebRequest "http://localhost:5000/" -UseBasicParsing
if ($dashboard.StatusCode -ne 200) {
  throw "Dashboard health check failed with HTTP $($dashboard.StatusCode)."
}

Write-Host "Checking vulnerable app..."
$vulnerable = Invoke-WebRequest "http://localhost:8000/" -UseBasicParsing
if ($vulnerable.StatusCode -ne 200) {
  throw "Vulnerable app health check failed with HTTP $($vulnerable.StatusCode)."
}

Write-Host "Demo is ready:" -ForegroundColor Green
Write-Host "  Dashboard:       http://localhost:5000"
Write-Host "  Vulnerable app:  http://localhost:8000"
Write-Host "  SQLi password:   ' OR '1'='1"

if (-not $NoBrowser) {
  Start-Process "http://localhost:5000"
  Start-Process "http://localhost:8000"
}
