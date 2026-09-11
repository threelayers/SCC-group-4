param(
  [switch]$CollectLive,
  [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$vulnerableApp = Join-Path $repoRoot "vulnerable-app"

function Test-DockerReady {
  $ErrorActionPreference = "Continue"
  & "docker" info 1>$null 2>$null
  return $LASTEXITCODE -eq 0
}

function Wait-ForDocker {
  if (Test-DockerReady) {
    return
  }

  $dockerDesktop = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
  if (Test-Path $dockerDesktop) {
    Write-Host "Docker Desktop is not ready. Starting it..."
    Start-Process -FilePath $dockerDesktop | Out-Null

    for ($attempt = 1; $attempt -le 30; $attempt++) {
      Start-Sleep -Seconds 2
      if (Test-DockerReady) {
        return
      }
    }
  }

  throw "Docker Desktop is not running or its Linux engine is unavailable. Start Docker Desktop, wait until it says Running, then rerun .\demo.ps1."
}

function Invoke-Checked {
  param(
    [string]$Command,
    [string[]]$Arguments,
    [string]$WorkingDirectory
  )

  Push-Location $WorkingDirectory
  try {
    & $Command @Arguments
    $status = $LASTEXITCODE
  } finally {
    Pop-Location
  }

  if ($status -ne 0) {
    throw "Command failed: $Command $($Arguments -join ' ')"
  }
}

function Wait-ForHttp {
  param(
    [string]$Url,
    [string]$ServiceName
  )

  for ($attempt = 1; $attempt -le 30; $attempt++) {
    try {
      $response = Invoke-WebRequest $Url -UseBasicParsing -TimeoutSec 3
      if ($response.StatusCode -eq 200) {
        return
      }
    } catch {
      # The container may still be starting. Retry until the timeout.
    }
    Start-Sleep -Seconds 2
  }

  throw "$ServiceName did not become reachable at $Url. Check its Docker logs."
}

Wait-ForDocker

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
Wait-ForHttp "http://localhost:5000/" "Dashboard"

Write-Host "Checking vulnerable app..."
Wait-ForHttp "http://localhost:8000/" "Vulnerable app"

Write-Host "Demo is ready:" -ForegroundColor Green
Write-Host "  Dashboard:       http://localhost:5000"
Write-Host "  Vulnerable app:  http://localhost:8000"
Write-Host "  SQLi password:   ' OR '1'='1"

if (-not $NoBrowser) {
  Start-Process "http://localhost:5000"
  Start-Process "http://localhost:8000"
}
