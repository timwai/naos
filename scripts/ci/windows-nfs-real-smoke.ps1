$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "real Windows NFS smoke test must run elevated because Client for NFS mounts require administrator privileges"
}

foreach ($command in @("mount.exe", "umount.exe", "rpcinfo.exe")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "missing required command: $command. Install Client for NFS and its management tools on this dedicated runner"
    }
}

$server = $env:NAOS_NFS_SMOKE_SERVER
if ([string]::IsNullOrWhiteSpace($server) -or -not (Test-Path -LiteralPath $server -PathType Leaf)) {
    throw "NAOS_NFS_SMOKE_SERVER must point to an nfs-smoke-server.exe binary"
}

$nfsPort = if ($env:NAOS_NFS_SMOKE_NFS_PORT) { [int]$env:NAOS_NFS_SMOKE_NFS_PORT } else { 32049 }
$mountPort = if ($env:NAOS_NFS_SMOKE_MOUNT_PORT) { [int]$env:NAOS_NFS_SMOKE_MOUNT_PORT } else { 32048 }
$nlmPort = if ($env:NAOS_NFS_SMOKE_NLM_PORT) { [int]$env:NAOS_NFS_SMOKE_NLM_PORT } else { 32047 }
$nsmPort = if ($env:NAOS_NFS_SMOKE_NSM_PORT) { [int]$env:NAOS_NFS_SMOKE_NSM_PORT } else { 32046 }
$rpcbindAddress = if ($env:NAOS_NFS_SMOKE_RPCBIND) { $env:NAOS_NFS_SMOKE_RPCBIND } else { "127.0.0.1:111" }

$servicePorts = @($nfsPort, $mountPort, $nlmPort, $nsmPort)
foreach ($port in $servicePorts) {
    if ($port -lt 1 -or $port -gt 65535) {
        throw "invalid NFS smoke service port: $port"
    }
}
if (($servicePorts | Select-Object -Unique).Count -ne $servicePorts.Count) {
    throw "NFS, MOUNT, NLM, and NSM smoke ports must be distinct"
}

if ($rpcbindAddress -ne "127.0.0.1:111") {
    throw "Windows smoke test currently requires NAOS_NFS_SMOKE_RPCBIND=127.0.0.1:111"
}

$portmapperReachable = Test-NetConnection -ComputerName 127.0.0.1 -Port 111 -InformationLevel Quiet
if (-not $portmapperReachable) {
    throw "no TCP portmapper is listening on 127.0.0.1:111; configure the dedicated Windows NFS runner before running this smoke test"
}

$driveLetter = @("Z", "Y", "X", "W", "V", "U", "T") |
    Where-Object { -not (Get-PSDrive -Name $_ -ErrorAction SilentlyContinue) } |
    Select-Object -First 1
if (-not $driveLetter) {
    throw "no free drive letter is available for the NFS smoke mount"
}

$root = Join-Path $env:SystemRoot ("Temp\naos-nfs-smoke-" + [guid]::NewGuid().ToString("N"))
$share = Join-Path $root "share"
$serverOut = Join-Path $root "server.out.log"
$serverErr = Join-Path $root "server.err.log"
$mountRoot = "${driveLetter}:\"
$serverProcess = $null
$mounted = $false

New-Item -ItemType Directory -Force -Path $share | Out-Null

try {
    $env:NAOS_NFS_SMOKE_RPCBIND = $rpcbindAddress
    $serverProcess = Start-Process -FilePath $server -ArgumentList @($share, $nfsPort, $mountPort) -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr -PassThru

    $registered = $false
    for ($attempt = 0; $attempt -lt 80; $attempt++) {
        if ($serverProcess.HasExited) {
            throw "NFS smoke server exited before registering with portmapper"
        }

        $registrations = (& rpcinfo.exe -p 127.0.0.1 2>$null | Out-String)
        $nfsPattern = "(?m)^\s*100003\s+3\s+tcp\s+$nfsPort(?:\s+.*)?$"
        $mountPattern = "(?m)^\s*100005\s+3\s+tcp\s+$mountPort(?:\s+.*)?$"
        $nlmTcpPattern = "(?m)^\s*100021\s+4\s+tcp\s+$nlmPort(?:\s+.*)?$"
        $nlmUdpPattern = "(?m)^\s*100021\s+4\s+udp\s+$nlmPort(?:\s+.*)?$"
        $nsmTcpPattern = "(?m)^\s*100024\s+1\s+tcp\s+$nsmPort(?:\s+.*)?$"
        $nsmUdpPattern = "(?m)^\s*100024\s+1\s+udp\s+$nsmPort(?:\s+.*)?$"
        if (
            $registrations -match $nfsPattern -and
            $registrations -match $mountPattern -and
            $registrations -match $nlmTcpPattern -and
            $registrations -match $nlmUdpPattern -and
            $registrations -match $nsmTcpPattern -and
            $registrations -match $nsmUdpPattern
        ) {
            $registered = $true
            break
        }
        Start-Sleep -Milliseconds 100
    }

    if (-not $registered) {
        throw "naos NFSv3/MOUNTv3/NLMv4/NSMv1 registrations did not appear in the local portmapper"
    }

    $mountOutput = (& mount.exe -o anon,nolock "127.0.0.1:/ci-share" "${driveLetter}:" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "Windows Client for NFS could not mount the naos export: $mountOutput"
    }
    $mounted = $true

    $mountedFile = Join-Path $mountRoot "roundtrip.txt"
    $shareFile = Join-Path $share "roundtrip.txt"

    [IO.File]::WriteAllText($mountedFile, "created", [Text.UTF8Encoding]::new($false))
    if ([IO.File]::ReadAllText($mountedFile) -ne "created") {
        throw "mounted read after create returned unexpected content"
    }
    if ([IO.File]::ReadAllText($shareFile) -ne "created") {
        throw "backing share did not receive created content"
    }

    [IO.File]::WriteAllText($mountedFile, "truncated", [Text.UTF8Encoding]::new($false))
    if ([IO.File]::ReadAllText($mountedFile) -ne "truncated") {
        throw "mounted read after truncate returned unexpected content"
    }
    if ([IO.File]::ReadAllText($shareFile) -ne "truncated") {
        throw "backing share did not receive truncated content"
    }

    $unicodeName = "naos-你好-é.txt"
    $unicodeMounted = Join-Path $mountRoot $unicodeName
    $unicodeShare = Join-Path $share $unicodeName
    $unicodeContent = "Windows NFS Unicode: 你好 / café / Δ"
    [IO.File]::WriteAllText($unicodeMounted, $unicodeContent, [Text.UTF8Encoding]::new($false))
    if ([IO.File]::ReadAllText($unicodeMounted) -ne $unicodeContent) {
        throw "mounted Unicode filename/content round-trip failed"
    }
    if ([IO.File]::ReadAllText($unicodeShare) -ne $unicodeContent) {
        throw "backing share did not receive Unicode filename/content correctly"
    }

    $largeMounted = Join-Path $mountRoot "large.bin"
    $largeShare = Join-Path $share "large.bin"
    $payload = [byte[]]::new(2 * 1024 * 1024)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($payload)
    }
    finally {
        $rng.Dispose()
    }

    $stream = [IO.File]::Open(
        $largeMounted,
        [IO.FileMode]::Create,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $stream.Write($payload, 0, $payload.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }

    $mountedHash = (Get-FileHash -LiteralPath $largeMounted -Algorithm SHA256).Hash
    $shareHash = (Get-FileHash -LiteralPath $largeShare -Algorithm SHA256).Hash
    if ($mountedHash -ne $shareHash) {
        throw "large binary write/read hash mismatch between NFS mount and backing share"
    }

    $renamedMounted = Join-Path $mountRoot "renamed.txt"
    $renamedShare = Join-Path $share "renamed.txt"
    Move-Item -LiteralPath $mountedFile -Destination $renamedMounted
    if (-not (Test-Path -LiteralPath $renamedShare) -or (Test-Path -LiteralPath $shareFile)) {
        throw "rename did not propagate to the backing share"
    }

    $mountedDir = Join-Path $mountRoot "dir"
    $shareDir = Join-Path $share "dir"
    New-Item -ItemType Directory -Path $mountedDir | Out-Null
    if (-not (Test-Path -LiteralPath $shareDir -PathType Container)) {
        throw "directory creation did not propagate to the backing share"
    }

    Get-ChildItem -LiteralPath $mountRoot | Out-Null
    Remove-Item -LiteralPath $mountedDir
    Remove-Item -LiteralPath $renamedMounted
    Remove-Item -LiteralPath $unicodeMounted
    Remove-Item -LiteralPath $largeMounted

    if (
        (Test-Path -LiteralPath $shareDir) -or
        (Test-Path -LiteralPath $renamedShare) -or
        (Test-Path -LiteralPath $unicodeShare) -or
        (Test-Path -LiteralPath $largeShare)
    ) {
        throw "delete did not propagate to the backing share"
    }

    Write-Host "real Windows NFSv3 mount/create/truncate/read/write/Unicode/large-file/flush/rename/delete smoke test passed"
}
catch {
    if (Test-Path -LiteralPath $serverOut) {
        Write-Host "----- naos NFS smoke server stdout -----"
        Get-Content -LiteralPath $serverOut
    }
    if (Test-Path -LiteralPath $serverErr) {
        Write-Host "----- naos NFS smoke server stderr -----"
        Get-Content -LiteralPath $serverErr
    }
    throw
}
finally {
    if ($mounted) {
        & umount.exe "${driveLetter}:" *> $null
    }
    if ($serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
        $serverProcess.WaitForExit()
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
