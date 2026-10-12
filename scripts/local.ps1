# Construye y arranca Ominous Security en http://localhost:8080 (Windows / PowerShell)
#
#   .\scripts\local.ps1            construye la imagen y la arranca con Docker Desktop
#   .\scripts\local.ps1 full       igual, con Gitleaks, Semgrep, Trivy y CodeQL (imagen más grande)
#   .\scripts\local.ps1 down       la para
#   .\scripts\local.ps1 logs       muestra los logs
#   .\scripts\local.ps1 rebuild    reconstruye desde cero y arranca
#   .\scripts\local.ps1 node       arranca sin Docker, con el Node.js de tu máquina
param([string]$Command = 'up')
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if (-not $env:OMINOUS_PORT) { $env:OMINOUS_PORT = '8080' }
if (-not $env:OMINOUS_CLONES) { $env:OMINOUS_CLONES = Join-Path $HOME 'ominous-clones' }
$url = "http://localhost:$($env:OMINOUS_PORT)"

function Wait-Ready {
  Write-Host -NoNewline 'Esperando a que arranque'
  for ($i = 0; $i -lt 60; $i++) {
    try {
      $r = Invoke-WebRequest -UseBasicParsing "$url/api/health" -TimeoutSec 2
      if ($r.StatusCode -eq 200) { Write-Host "`nOminous Security lista en $url"; Write-Host "  Clones en $($env:OMINOUS_CLONES)"; return }
    } catch { }
    Write-Host -NoNewline '.'; Start-Sleep -Seconds 1
  }
  docker compose logs --tail 30 app
  throw 'No ha arrancado en 60 s.'
}

switch ($Command) {
  'up'      { New-Item -ItemType Directory -Force $env:OMINOUS_CLONES | Out-Null; docker compose up -d --build --force-recreate; Wait-Ready; Start-Process $url }
  'full'    { New-Item -ItemType Directory -Force $env:OMINOUS_CLONES | Out-Null; docker compose -f compose.yaml -f compose.full.yaml up -d --build --force-recreate; Wait-Ready; Start-Process $url }
  'rebuild' { New-Item -ItemType Directory -Force $env:OMINOUS_CLONES | Out-Null; docker compose build --no-cache --pull; docker compose up -d --force-recreate; Wait-Ready }
  'down'    { docker compose down }
  'logs'    { docker compose logs -f app }
  'node'    {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'No encuentro Node.js 18 o superior (https://nodejs.org).' }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'No encuentro git.' }
    if (-not (Test-Path node_modules)) { npm ci --omit=dev --ignore-scripts }
    $env:PORT = $env:OMINOUS_PORT; $env:CLONE_DIR = $env:OMINOUS_CLONES
    node server.js
  }
  default   { Get-Content $PSCommandPath -TotalCount 8 | Select-Object -Skip 1; exit 1 }
}
