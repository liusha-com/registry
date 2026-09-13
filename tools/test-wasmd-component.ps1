#!/usr/bin/env powershell
[CmdletBinding()]
param(
    [string]$Wasmd = 'D:\code\wasmd\target\release\wasmd.exe',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Component = Join-Path $Root 'artifacts/registry.wasm'
$WasmdRoot = Join-Path (Split-Path -Parent $Root) 'wasmd'
$DefaultWasmd = Join-Path $WasmdRoot 'target/release/wasmd.exe'
$Token = 'm16-6-smoke-admin-token-with-at-least-32-characters'
$RunRoot = Join-Path $Root ("target/wasmd-component-smoke-{0}" -f ([guid]::NewGuid().ToString('N')))

if (-not $SkipBuild) {
    & (Join-Path $PSScriptRoot 'build-wasm-service.ps1')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if ([System.IO.Path]::GetFullPath($Wasmd) -eq [System.IO.Path]::GetFullPath($DefaultWasmd)) {
        $Cargo = Join-Path $env:USERPROFILE '.cargo/bin/cargo.exe'
        if (-not (Test-Path -LiteralPath $Cargo)) { throw "cargo not found at $Cargo" }
        & $Cargo build --manifest-path (Join-Path $WasmdRoot 'Cargo.toml') --release --locked -p wasmd-cli
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}
if (-not (Test-Path -LiteralPath $Wasmd)) { throw "wasmd not found at $Wasmd" }
if (-not (Test-Path -LiteralPath $Component)) { throw "Registry component not found at $Component" }
New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null

$Listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$Listener.Start()
$Port = ([System.Net.IPEndPoint]$Listener.LocalEndpoint).Port
$Listener.Stop()
$Base = "http://127.0.0.1:$Port"
$Arguments = @(
    'serve', $Component,
    '--listen', "127.0.0.1:$Port",
    '--data', $RunRoot,
    '--fuel', '2000000000',
    '--timeout-ms', '180000',
    '--env', "WASMD_REGISTRY_ADMIN_TOKEN=$Token"
)
$Process = Start-Process -FilePath $Wasmd -ArgumentList $Arguments -PassThru -WindowStyle Hidden

try {
    $Ready = $false
    for ($Attempt = 0; $Attempt -lt 120; $Attempt++) {
        if ($Process.HasExited) { throw "wasmd exited with code $($Process.ExitCode)" }
        try {
            if ((Invoke-WebRequest -UseBasicParsing -Uri "$Base/healthz" -TimeoutSec 2).Content -eq "ok`n") {
                $Ready = $true
                break
            }
        } catch {}
        Start-Sleep -Milliseconds 250
    }
    if (-not $Ready) { throw 'Registry component did not become ready' }

    $Ui = Invoke-WebRequest -UseBasicParsing -Uri "$Base/" -TimeoutSec 30
    if ($Ui.StatusCode -ne 200 -or $Ui.Content -notmatch 'Wasmd Registry') { throw 'embedded UI smoke test failed' }
    $Info = Invoke-RestMethod -Uri "$Base/v1/info" -TimeoutSec 30
    if ($Info.registry_version -ne '0.1-wasi-http' -or $Info.features -notcontains 'wasi-http-proxy') {
        throw 'standard WASI HTTP discovery metadata is missing'
    }

    $Headers = @{ Authorization = "Bearer $Token" }
    $Namespace = '{"name":"smoke","description":"WASI HTTP component smoke test"}'
    Invoke-RestMethod -Method Post -Uri "$Base/v1/namespaces" -Headers $Headers `
        -ContentType 'application/json' -Body $Namespace -TimeoutSec 30 | Out-Null

    $Bytes = [System.IO.File]::ReadAllBytes($Component)
    $Hash = [System.Security.Cryptography.SHA256]::Create()
    try { $Hex = ([BitConverter]::ToString($Hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $Hash.Dispose() }
    $Digest = "sha256:$Hex"
    Invoke-RestMethod -Method Put -Uri "$Base/v1/blobs/$Digest" -Headers $Headers `
        -ContentType 'application/wasm' -Body $Bytes -TimeoutSec 240 | Out-Null

    $Analysis = Invoke-RestMethod -Uri "$Base/v1/blobs/$Digest/component" -TimeoutSec 60
    if ($Analysis.exports.name -notcontains 'wasi:http/incoming-handler@0.2.4') {
        throw 'Registry did not extract the standard incoming-handler export'
    }
    $Manifest = @{
        schema = 'wasmd.package/v0'; namespace = 'smoke'; name = 'registry'; version = '16.6.0'
        description = 'Registry WASI HTTP smoke package'; license = 'Apache-2.0'
        artifacts = @(@{ digest = $Digest; size = $Bytes.Length; media_type = 'application/wasm' })
    } | ConvertTo-Json -Depth 8 -Compress
    Invoke-RestMethod -Method Post -Uri "$Base/v1/packages/smoke/registry/versions" `
        -Headers $Headers -ContentType 'application/json' -Body $Manifest -TimeoutSec 60 | Out-Null
    $Release = Invoke-RestMethod -Uri "$Base/v1/packages/smoke/registry/16.6.0" -TimeoutSec 30
    if ($Release.record.version -ne '16.6.0') { throw 'published component was not resolved' }

    Write-Host "M16.6 standard wasi:http/proxy Registry smoke test passed at $Base"
}
finally {
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force
        $Process.WaitForExit()
    }
}
