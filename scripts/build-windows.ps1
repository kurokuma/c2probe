[CmdletBinding()]
param(
    [string]$OutputDirectory = 'dist'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows)) {
    throw 'This script must run on Windows. Use build-linux.sh on Linux.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot $OutputDirectory
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw 'cargo was not found. Install Rust 1.94 or later with the MSVC toolchain.'
}

function Invoke-Cargo {
    param([Parameter(Mandatory)][string[]]$CargoArguments)
    & cargo @CargoArguments
    if ($LASTEXITCODE -ne 0) {
        throw "cargo $($CargoArguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

Push-Location $repoRoot
try {
    Invoke-Cargo @('fmt', '--all', '--', '--check')
    Invoke-Cargo @('clippy', '--locked', '--all-targets', '--', '-D', 'warnings')
    Invoke-Cargo @('test', '--locked', '--all-targets')
    Invoke-Cargo @('build', '--locked', '--release')

    $manifest = Get-Content -LiteralPath 'Cargo.toml' -Raw
    $versionMatch = [regex]::Match($manifest, '(?m)^version\s*=\s*"([^"]+)"')
    if (-not $versionMatch.Success) {
        throw 'Unable to read the package version from Cargo.toml.'
    }

    $packageArch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
        'X64'   { 'x86_64' }
        'Arm64' { 'aarch64' }
        default { throw "Unsupported Windows architecture: $_" }
    }
    $packageName = "c2probe-$($versionMatch.Groups[1].Value)-windows-$packageArch"
    $stage = Join-Path $OutputDirectory $packageName
    $archive = Join-Path $OutputDirectory "$packageName.zip"
    $checksum = Join-Path $OutputDirectory "$packageName.sha256"

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    foreach ($path in @($stage, $archive, $checksum)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
    New-Item -ItemType Directory -Path $stage | Out-Null

    Copy-Item -LiteralPath 'target\release\c2probe.exe' -Destination $stage
    Copy-Item -LiteralPath 'target\release\nse2yaml.exe' -Destination $stage
    Copy-Item -LiteralPath 'probes' -Destination $stage -Recurse
    Copy-Item -LiteralPath 'docs' -Destination $stage -Recurse
    Copy-Item -LiteralPath 'README.md', 'spec.md' -Destination $stage
    Compress-Archive -LiteralPath $stage -DestinationPath $archive -CompressionLevel Optimal

    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash *$([System.IO.Path]::GetFileName($archive))" |
        Set-Content -LiteralPath $checksum -Encoding ascii

    & (Join-Path $stage 'c2probe.exe') --help | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'packaged c2probe.exe --help failed'
    }
    & (Join-Path $stage 'nse2yaml.exe') --help | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'packaged nse2yaml.exe --help failed'
    }

    Write-Host "Created: $archive"
    Write-Host "Checksum: $checksum"
    Write-Warning 'The Windows build supports probe mode and DSL development. Raw SYN discovery is Linux-only.'
}
finally {
    Pop-Location
}
