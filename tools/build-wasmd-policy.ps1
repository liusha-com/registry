#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [string]$Output = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts/registry-policy.wasm')
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Cargo = Join-Path $env:USERPROFILE '.cargo/bin/cargo.exe'
$Rustup = Join-Path $env:USERPROFILE '.cargo/bin/rustup.exe'
if (-not (Test-Path -LiteralPath $Cargo)) { throw "cargo not found at $Cargo" }
if (-not (Test-Path -LiteralPath $Rustup)) { throw "rustup not found at $Rustup" }

& $Rustup target add wasm32-wasip1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Cargo build --manifest-path (Join-Path $Root 'guest/Cargo.toml') --target wasm32-wasip1 --release --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$source = Join-Path $Root 'guest/target/wasm32-wasip1/release/wasmd-registry-policy.wasm'
$parent = Split-Path -Parent $Output
New-Item -ItemType Directory -Force -Path $parent | Out-Null
Copy-Item -LiteralPath $source -Destination $Output -Force
Write-Host "Built $Output"
