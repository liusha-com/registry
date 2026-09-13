#!/usr/bin/env powershell
[CmdletBinding()]
param(
    [string]$Output
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Output)) {
    $Output = Join-Path $Root 'artifacts/registry.wasm'
}
$Cargo = Join-Path $env:USERPROFILE '.cargo/bin/cargo.exe'
$Rustup = Join-Path $env:USERPROFILE '.cargo/bin/rustup.exe'
if (-not (Test-Path -LiteralPath $Cargo)) { throw "cargo not found at $Cargo" }
if (-not (Test-Path -LiteralPath $Rustup)) { throw "rustup not found at $Rustup" }

& $Rustup target add wasm32-wasip2
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Cargo build --manifest-path (Join-Path $Root 'service-guest/Cargo.toml') --target wasm32-wasip2 --release --locked -j 1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$Source = Join-Path $Root 'service-guest/target/wasm32-wasip2/release/wasmd_registry_service.wasm'
$Parent = Split-Path -Parent $Output
New-Item -ItemType Directory -Force -Path $Parent | Out-Null
Copy-Item -LiteralPath $Source -Destination $Output -Force
Write-Host "Built standard wasi:http/proxy Registry component: $Output"
