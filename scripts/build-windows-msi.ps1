# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Build the Karst client MSI: cargo builds karstd.exe/karst.exe natively,
# then WiX v6 (`wix build`, a .NET global tool) packages them with
# packaging/windows/Product.wxs — see that file's own header for what is
# and is not in the package. Needs a real Windows machine: the .NET tool
# itself is cross-platform, but karstd.exe is not, and the CI job that
# calls this (.github/workflows/deliverables.yml's `windows-package`)
# builds and installs on the same `windows-latest` runner rather than
# cross-compiling, the same reason the SCM/NRPT work before it was
# validated against real Windows CI rather than a cross-compile check
# alone.
#
# Usage:
#   pwsh scripts/build-windows-msi.ps1 [-Version <x.y.z>] [-OutputDir <dir>]
#
# -Version defaults to $env:VERSION (scripts/release-version.sh's first
# output line) with the same "0.0.0+git.<sha>" fallback that script uses,
# sanitized to the plain x.y.z MSI's ProductVersion requires — WiX rejects
# anything else, so a pre-release label or `+git.<sha>` suffix is stripped
# here rather than fed in and left to fail deep inside `wix build`.
#
# -OutputDir defaults to dist/windows. The one caller that overrides it is
# CI's upgrade-fixture build (deliverables.yml), which also passes a
# distinct -Version one release higher than the real build — see that
# job's comment for why a fixture, not the real build's own output,
# exercises the upgrade path plans/phase-5/07-windows-client.md §11
# criterion 6 asks for.

param(
    [string]$Version = $(if ($env:VERSION) { $env:VERSION } else { "0.0.0" }),
    [string]$OutputDir = "dist/windows"
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path "$PSScriptRoot/..").Path
Set-Location $root

# WiX's ProductVersion is major.minor.build, each a plain non-negative
# integer — no pre-release label, no build metadata. `scripts/release-version.sh`
# already keeps VERSION itself clean on a real tag (that stripping is what
# RELEASE and KARST_VERSION are for instead — see its own header), so this
# only ever actually trims something on the "0.0.0+git.<sha>" push-build
# fallback above.
$msiVersion = ($Version -split '[-+]')[0]
if ($msiVersion -notmatch '^\d+\.\d+\.\d+$') {
    Write-Error "VERSION '$Version' does not reduce to a plain x.y.z for the MSI (`$msiVersion`); pass -Version explicitly."
}

Write-Host "==> cargo build --release (karstd, karst)"
cargo build --locked --release --package karstd --package karst-cli
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$sourceDir = Join-Path $root "target/release"
foreach ($exe in @("karstd.exe", "karst.exe")) {
    if (-not (Test-Path (Join-Path $sourceDir $exe))) {
        Write-Error "cargo build did not produce $exe in $sourceDir"
    }
}

# ── WiX ──────────────────────────────────────────────────────────────────
#
# Pinned exactly, both here and for the extension below: an unpinned `wix
# extension add` resolves whatever is newest at the moment CI happens to
# run, and a wix/extension version mismatch fails at `wix build` with an
# error that names neither this script nor Product.wxs.
#
# 6.0.2, not the newer 7.x: WiX Toolset v7 requires accepting FireGiant's
# paid Open Source Maintenance Fee EULA before `wix build` will even run
# ("WIX7015" — found the hard way, failing this exact step on real CI).
# 6.0.2 is the last release under WiX's original open-source licensing and
# has every feature this package uses (`StandardDirectory`, the unified
# `<Package>` element, `WixToolset.Firewall.wixext`) — nothing here is
# lost by staying on it.
$wixVersion = "6.0.2"

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Host "==> installing wix $wixVersion"
    dotnet tool install --global wix --version $wixVersion
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    # `dotnet tool install --global` is a no-op on PATH until a new shell —
    # this process's own PATH needs the same update a fresh shell would
    # pick up automatically, or the `wix` invocations below fail with
    # "command not found" despite having just installed successfully.
    $toolsPath = Join-Path $env:USERPROFILE ".dotnet/tools"
    if ($env:PATH -notlike "*$toolsPath*") {
        $env:PATH = "$toolsPath;$env:PATH"
    }
}

Write-Host "==> wix extension add WixToolset.Firewall.wixext/$wixVersion"
wix extension add "WixToolset.Firewall.wixext/$wixVersion" --global
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$msiPath = Join-Path $OutputDir "karst-$Version-x64.msi"

Write-Host "==> wix build -> $msiPath (ProductVersion $msiVersion)"
# `-arch x64`: Product.wxs itself carries no architecture attribute (WiX
# v6's `Package` element has none — see that file's own comment) — this
# flag is what makes every Component/File default to a 64-bit component
# and stamps the MSI's template summary "x64" rather than WiX's x86
# default when the flag is omitted. Phase 5 is x64-only, so this is the
# one and only architecture this script ever builds.
wix build "packaging/windows/Product.wxs" `
    -arch x64 `
    -d "KarstVersion=$msiVersion" `
    -d "KarstSourceDir=$sourceDir" `
    -d "KarstConfigExample=$(Join-Path $root 'docs/karstd-example-windows.toml')" `
    -ext "WixToolset.Firewall.wixext/$wixVersion" `
    -o $msiPath
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$hash = Get-FileHash -Algorithm SHA256 $msiPath
# `<hash>␠␠<filename>` (two spaces, relative filename) — the same shape
# `shasum -a 256`/`sha256sum` produce, which is what
# scripts/release-manifest.sh and every other release script in this repo
# already expects to read back.
"$($hash.Hash.ToLower())  $(Split-Path -Leaf $msiPath)" | Out-File -Encoding ascii "$msiPath.sha256"

Write-Host "==> built $msiPath"
