$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "remote Windows NLM smoke test must run elevated because Client for NFS mounts require administrator privileges"
}

foreach ($command in @("mount.exe", "umount.exe", "rpcinfo.exe")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "missing required command: $command. Install Client for NFS and its management tools on this dedicated runner"
    }
}

$hostName = $env:NAOS_NFS_REMOTE_HOST
$export = if ($env:NAOS_NFS_REMOTE_EXPORT) { $env:NAOS_NFS_REMOTE_EXPORT } else { "/ci-share" }
$nfsPort = if ($env:NAOS_NFS_REMOTE_NFS_PORT) { [int]$env:NAOS_NFS_REMOTE_NFS_PORT } else { 2049 }
$mountPort = if ($env:NAOS_NFS_REMOTE_MOUNT_PORT) { [int]$env:NAOS_NFS_REMOTE_MOUNT_PORT } else { 20048 }
$restartTarget = $env:NAOS_NFS_REMOTE_RESTART_TARGET
$restartService = if ($env:NAOS_NFS_REMOTE_RESTART_SERVICE) { $env:NAOS_NFS_REMOTE_RESTART_SERVICE } else { "naosd" }
$graceWait = if ($env:NAOS_NFS_REMOTE_RESTART_GRACE_WAIT) { [int]$env:NAOS_NFS_REMOTE_RESTART_GRACE_WAIT } else { 35 }
$rpcTimeout = if ($env:NAOS_NFS_REMOTE_RESTART_RPC_TIMEOUT) { [int]$env:NAOS_NFS_REMOTE_RESTART_RPC_TIMEOUT } else { 60 }
$nlmProbe = $env:NAOS_NFS_REMOTE_NLM_PROBE

if ([string]::IsNullOrWhiteSpace($hostName)) {
    throw "NAOS_NFS_REMOTE_HOST is required"
}
if ($hostName -in @("localhost", "127.0.0.1", "::1")) {
    throw "remote Windows NLM smoke requires a separate NFS server host"
}
if (-not $export.StartsWith("/")) {
    throw "NAOS_NFS_REMOTE_EXPORT must be an absolute export path"
}
foreach ($port in @($nfsPort, $mountPort)) {
    if ($port -lt 1 -or $port -gt 65535) {
        throw "invalid NFS smoke port: $port"
    }
}
if ([string]::IsNullOrWhiteSpace($nlmProbe) -or -not (Test-Path -LiteralPath $nlmProbe -PathType Leaf)) {
    throw "NAOS_NFS_REMOTE_NLM_PROBE must point to the built nfs-nlm-probe.exe"
}

if (-not [string]::IsNullOrWhiteSpace($restartTarget)) {
    if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
        throw "restart/reclaim mode requires ssh.exe (OpenSSH Client)"
    }
    if ($restartTarget -notmatch "^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$") {
        throw "NAOS_NFS_REMOTE_RESTART_TARGET must be a simple user@host SSH target"
    }
    if ($restartService -notmatch "^[A-Za-z0-9_.@-]+$") {
        throw "invalid NAOS_NFS_REMOTE_RESTART_SERVICE"
    }
    if ($graceWait -lt 31 -or $graceWait -gt 300) {
        throw "NAOS_NFS_REMOTE_RESTART_GRACE_WAIT must be between 31 and 300 seconds"
    }
    if ($rpcTimeout -lt 5 -or $rpcTimeout -gt 300) {
        throw "NAOS_NFS_REMOTE_RESTART_RPC_TIMEOUT must be between 5 and 300 seconds"
    }
}

function Get-RpcRegistrations {
    (& rpcinfo.exe -p $hostName 2>$null | Out-String)
}

function Test-RemoteLockServices {
    $registrations = Get-RpcRegistrations
    return (
        $registrations -match "(?m)^\s*100021\s+4\s+udp\s+" -and
        $registrations -match "(?m)^\s*100024\s+1\s+udp\s+"
    )
}

function Wait-RemoteLockServices {
    $deadline = [DateTime]::UtcNow.AddSeconds($rpcTimeout)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-RemoteLockServices) {
            return
        }
        Start-Sleep -Seconds 1
    }
    throw "remote NLMv4/NSMv1 RPC registrations did not recover within $rpcTimeout seconds"
}

if (-not (Test-RemoteLockServices)) {
    $registrations = Get-RpcRegistrations
    throw "remote server does not advertise NLMv4 and NSMv1 over UDP. rpcinfo output:`n$registrations"
}

$driveLetter = @("Z", "Y", "X", "W", "V", "U", "T") |
    Where-Object { -not (Get-PSDrive -Name $_ -ErrorAction SilentlyContinue) } |
    Select-Object -First 1
if (-not $driveLetter) {
    throw "no free drive letter is available for the remote NFS lock mount"
}

$root = Join-Path $env:TEMP ("naos-windows-nlm-" + [guid]::NewGuid().ToString("N"))
$holderScript = Join-Path $root "holder.ps1"
$readyFile = Join-Path $root "holder.ready"
$releaseFile = Join-Path $root "holder.release"
$holderOut = Join-Path $root "holder.out.log"
$holderErr = Join-Path $root "holder.err.log"
$mountRoot = "${driveLetter}:\"
$mounted = $false
$holder = $null

New-Item -ItemType Directory -Force -Path $root | Out-Null

@'
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$ReadyFile,
    [Parameter(Mandatory = $true)][string]$ReleaseFile
)

$ErrorActionPreference = "Stop"
$stream = [IO.File]::Open(
    $Path,
    [IO.FileMode]::Open,
    [IO.FileAccess]::ReadWrite,
    [IO.FileShare]::ReadWrite
)
try {
    $stream.Lock(0, 1)
    [IO.File]::WriteAllText($ReadyFile, "locked")
    while (-not (Test-Path -LiteralPath $ReleaseFile)) {
        Start-Sleep -Milliseconds 100
    }
    $stream.Unlock(0, 1)
}
finally {
    $stream.Dispose()
}
'@ | Set-Content -LiteralPath $holderScript -Encoding utf8

function Start-LockHolder([string]$path) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $PSHOME "pwsh.exe"
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @(
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        $holderScript,
        "-Path",
        $path,
        "-ReadyFile",
        $readyFile,
        "-ReleaseFile",
        $releaseFile
    )) {
        [void]$start.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw "failed to start Windows NFS lock holder process"
    }
    return $process
}

function Wait-LockHolderReady([Diagnostics.Process]$process) {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $readyFile) {
            return
        }
        if ($process.HasExited) {
            $stderr = $process.StandardError.ReadToEnd()
            throw "Windows NFS lock holder exited before acquiring the lock: $stderr"
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Windows NFS lock holder did not acquire the lock within 15 seconds"
}

function Test-ConflictingLockDenied([string]$path) {
    $stream = [IO.File]::Open(
        $path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite
    )
    try {
        try {
            $stream.Lock(0, 1)
        }
        catch [IO.IOException] {
            return $true
        }
        $stream.Unlock(0, 1)
        return $false
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-ServerLockState([string]$fileName, [string]$expected) {
    & $nlmProbe $hostName $export $fileName $nfsPort $mountPort $expected
    if ($LASTEXITCODE -ne 0) {
        throw "direct NLM probe did not report expected state '$expected'"
    }
}

try {
    $mountOutput = (& mount.exe -o "anon,mtype=hard" "${hostName}:$export" "${driveLetter}:" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "Windows Client for NFS could not mount the remote naos export: $mountOutput"
    }
    $mounted = $true

    $lockFile = Join-Path $mountRoot ("naos-windows-nlm-" + [guid]::NewGuid().ToString("N") + ".txt")
    [IO.File]::WriteAllText($lockFile, "windows-remote-nlm", [Text.UTF8Encoding]::new($false))
    $fileName = [IO.Path]::GetFileName($lockFile)

    $holder = Start-LockHolder $lockFile
    Wait-LockHolderReady $holder

    if (-not (Test-ConflictingLockDenied $lockFile)) {
        throw "second Windows process unexpectedly acquired a conflicting NFS byte-range lock"
    }
    Assert-ServerLockState $fileName "locked"

    if (-not [string]::IsNullOrWhiteSpace($restartTarget)) {
        & ssh.exe -o BatchMode=yes -o ConnectTimeout=10 -- $restartTarget sudo systemctl restart $restartService
        if ($LASTEXITCODE -ne 0) {
            throw "remote naosd restart failed"
        }

        Wait-RemoteLockServices
        if ($holder.HasExited) {
            $stderr = $holder.StandardError.ReadToEnd()
            throw "Windows lock holder exited during server restart: $stderr"
        }

        Start-Sleep -Seconds $graceWait
        if (-not (Test-ConflictingLockDenied $lockFile)) {
            throw "conflicting Windows lock succeeded after server restart and grace period; the original lock was not reclaimed"
        }
        Assert-ServerLockState $fileName "locked"
    }

    New-Item -ItemType File -Force -Path $releaseFile | Out-Null
    if (-not $holder.WaitForExit(10000)) {
        throw "Windows NFS lock holder did not exit after release signal"
    }
    if ($holder.ExitCode -ne 0) {
        $stderr = $holder.StandardError.ReadToEnd()
        throw "Windows NFS lock holder failed while releasing the lock: $stderr"
    }

    if (Test-ConflictingLockDenied $lockFile) {
        throw "Windows NFS lock remained unavailable after the original holder released it"
    }
    Assert-ServerLockState $fileName "unlocked"

    Remove-Item -LiteralPath $lockFile -Force
    if ([string]::IsNullOrWhiteSpace($restartTarget)) {
        Write-Host "real Windows NFSv3 remote NLMv4 record-lock smoke test passed against $hostName"
    }
    else {
        Write-Host "real Windows NFSv3 remote NLMv4 restart/reclaim smoke test passed against $hostName"
    }
}
catch {
    if ($holder -and $holder.HasExited) {
        Write-Host "----- Windows NFS lock holder stdout -----"
        Write-Host $holder.StandardOutput.ReadToEnd()
        Write-Host "----- Windows NFS lock holder stderr -----"
        Write-Host $holder.StandardError.ReadToEnd()
    }
    throw
}
finally {
    if ($holder -and -not $holder.HasExited) {
        Stop-Process -Id $holder.Id -Force -ErrorAction SilentlyContinue
        $holder.WaitForExit()
    }
    if ($mounted) {
        & umount.exe "${driveLetter}:" *> $null
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
