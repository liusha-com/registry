#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [string]$WasmdRoot = 'D:\code\wasmd',
    [string]$SpecRoot = 'D:\code\spec'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Cargo = Join-Path $env:USERPROFILE '.cargo/bin/cargo.exe'
& $Cargo build --manifest-path (Join-Path $WasmdRoot 'Cargo.toml') --release -p wasmd-cli
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $PSScriptRoot 'build-wasmd-policy.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Cargo build --manifest-path (Join-Path $Root 'Cargo.toml') --bin wasmd-registry --bin wr --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$runRoot = Join-Path $Root ('target/wasmd-mode-smoke/' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $runRoot | Out-Null
$admin = 'wasmd-mode-admin-token-with-more-than-32-characters'
$env:WASMD_REGISTRY_LISTEN = "127.0.0.1:$port"
$env:WASMD_REGISTRY_DATABASE = Join-Path $runRoot 'registry.db'
$env:WASMD_REGISTRY_BLOB_DIR = Join-Path $runRoot 'blobs'
$env:WASMD_REGISTRY_TEMP_DIR = Join-Path $runRoot 'tmp'
$env:WASMD_REGISTRY_ADMIN_TOKEN = $admin
$env:WASMD_REGISTRY_WASMD_BIN = Join-Path $WasmdRoot 'target/release/wasmd.exe'
$env:WASMD_REGISTRY_WASM_POLICY = Join-Path $Root 'artifacts/registry-policy.wasm'
$server = Join-Path $Root 'target/debug/wasmd-registry.exe'
$client = Join-Path $Root 'target/debug/wr.exe'
$process = Start-Process -FilePath $server -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $runRoot 'stdout.log') `
    -RedirectStandardError (Join-Path $runRoot 'stderr.log')
try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 80; $attempt++) {
        try {
            Invoke-RestMethod -Uri "http://127.0.0.1:$port/readyz" | Out-Null
            $ready = $true
            break
        } catch { Start-Sleep -Milliseconds 250 }
    }
    if (-not $ready) { throw 'Registry did not become ready in Wasmd mode.' }
    $info = Invoke-RestMethod -Uri "http://127.0.0.1:$port/v1/info"
    if ($info.admission_engine -ne 'wasmd') { throw 'Registry did not select Wasmd admission.' }
    & $client --registry "http://127.0.0.1:$port" --token $admin namespace create smoke | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Namespace creation failed.' }
    $wasm = Join-Path $SpecRoot 'spectec/test-interpreter/sample.wasm'
    $upload = (& $client --registry "http://127.0.0.1:$port" --token $admin upload $wasm | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { throw 'Blob upload failed.' }
    $manifest = @{
        schema = 'wasmd.package/v0'; namespace = 'smoke'; name = 'sample'; version = '1.0.0'
        artifacts = @(@{name='module';digest=$upload.digest;size=(Get-Item $wasm).Length;media_type='application/wasm';kind='core-module'})
        dependencies = @{}; annotations = @{}
    }
    $headers = @{Authorization = "Bearer $admin"}
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$port/v1/packages/smoke/sample/versions" `
        -Headers $headers -ContentType 'application/json' -Body ($manifest | ConvertTo-Json -Depth 10) | Out-Null
    $manifest.name = 'bad'
    $manifest.version = '01.0.0'
    $rejected = $false
    try {
        Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$port/v1/packages/smoke/bad/versions" `
            -Headers $headers -ContentType 'application/json' -Body ($manifest | ConvertTo-Json -Depth 10) | Out-Null
    } catch { $rejected = $_.ErrorDetails.Message -match 'policy_rejected' }
    if (-not $rejected) { throw 'Invalid manifest was not rejected by Wasmd policy.' }
    Write-Host "Wasmd Registry mode passed: engine=wasmd port=$port policy_rejection=true"
} finally {
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
}
