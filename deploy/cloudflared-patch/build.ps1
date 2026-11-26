param(
    [string]$TargetOS = $env:GOOS,
    [string]$TargetArch = $env:GOARCH
)

$ErrorActionPreference = 'Stop'

function Invoke-Checked([scriptblock]$Operation) {
    & $Operation
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Operation"
    }
}

$locked = @{}
foreach ($line in Get-Content -LiteralPath (Join-Path $PSScriptRoot 'upstream.lock')) {
    if ($line -cnotmatch '^([a-z0-9_]+)=(\S+)$') {
        throw 'Invalid upstream.lock entry'
    }
    $locked.Add($Matches[1], $Matches[2])
}
if ($locked.Count -ne 4 -or $locked.repo -cnotmatch '^https://github\.com/cloudflare/cloudflared\.git$' -or
    $locked.tag -cnotmatch '^\d+\.\d+\.\d+$' -or $locked.commit -cnotmatch '^[0-9a-f]{40}$' -or
    $locked.patch_sha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw 'Invalid upstream.lock'
}

$patch = Join-Path $PSScriptRoot 'vanora-pinned-origin.patch'
$actualPatchHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $patch).Hash.ToLowerInvariant()
if ($actualPatchHash -cne $locked.patch_sha256) {
    throw 'Patch SHA-256 does not match upstream.lock'
}
Write-Host "Verified patch SHA-256 $actualPatchHash"

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$dist = Join-Path $repoRoot 'dist'
$source = Join-Path $dist 'cloudflared-src'
$output = Join-Path $dist 'cloudflared'
if (-not (Test-Path -LiteralPath (Join-Path $source '.git'))) {
    Invoke-Checked { git init --quiet $source }
}
$tagRef = "refs/tags/$($locked.tag)"
$tagCommit = git -C $source rev-parse --quiet --verify "${tagRef}^{commit}"
if ($LASTEXITCODE -ne 0 -or $tagCommit -cne $locked.commit) {
    Invoke-Checked { git -C $source fetch --no-tags --depth=1 $locked.repo "${tagRef}:${tagRef}" }
    $tagCommit = Invoke-Checked { git -C $source rev-parse --verify "${tagRef}^{commit}" }
}
if ($tagCommit -cne $locked.commit) {
    throw 'Upstream tag does not resolve to the locked commit'
}
Write-Host "Verified cloudflared $($locked.tag) $tagCommit"

$hostOS, $hostArch = Invoke-Checked { go env GOHOSTOS GOHOSTARCH }
if (-not $TargetOS) { $TargetOS = $hostOS }
if (-not $TargetArch) { $TargetArch = $hostArch }
$binaryName = 'cloudflared-vanora'
if ($TargetOS -ceq 'windows') { $binaryName += '.exe' }

$checkout = [IO.Path]::GetFullPath((Join-Path $dist "cloudflared-build-$([Guid]::NewGuid().ToString('N'))"))
$distPrefix = [IO.Path]::GetFullPath($dist).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $checkout.StartsWith($distPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Build checkout must be inside dist'
}
$previousOS, $previousArch, $previousCGO, $previousGoWork = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED, $env:GOWORK
Invoke-Checked { git -C $source worktree add --quiet --detach $checkout $locked.commit }
try {
    $checkedOut = Invoke-Checked { git -C $checkout rev-parse HEAD }
    if ($checkedOut -cne $locked.commit) { throw 'Build checkout is at the wrong commit' }
    Invoke-Checked { git -C $checkout apply --check $patch }
    Write-Host 'git apply --check passed'
    Invoke-Checked { git -C $checkout apply $patch }

    Push-Location -LiteralPath $checkout
    try {
        $env:GOOS, $env:GOARCH, $env:CGO_ENABLED, $env:GOWORK = $hostOS, $hostArch, '0', 'off'
        Invoke-Checked { go test -mod=readonly ./ingress ./orchestration ./cmd/cloudflared/tunnel }
        $env:GOOS, $env:GOARCH = $TargetOS, $TargetArch
        $linkFlags = "-s -w -X main.Version=$($locked.tag)-vanora"
        Invoke-Checked { go build -mod=readonly -buildvcs=false -trimpath -ldflags $linkFlags -o $binaryName ./cmd/cloudflared }
    } finally {
        Pop-Location
    }

    $binary = Join-Path $checkout $binaryName
    $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$binary.sha256", "$digest  $binaryName`n", [Text.Encoding]::ASCII)
    $null = New-Item -ItemType Directory -Path $output -Force
    $artifact = Join-Path $output $binaryName
    Move-Item -LiteralPath $binary -Destination $artifact -Force
    Move-Item -LiteralPath "$binary.sha256" -Destination "$artifact.sha256" -Force
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash.ToLowerInvariant() -cne $digest) {
        throw 'Packaged binary SHA-256 verification failed'
    }
    Write-Host "Built $TargetOS/$TargetArch $artifact"
    Write-Host "SHA-256 $digest"
} finally {
    $env:GOOS, $env:GOARCH, $env:CGO_ENABLED, $env:GOWORK = $previousOS, $previousArch, $previousCGO, $previousGoWork
    Invoke-Checked { git -C $source worktree remove --force $checkout }
}
