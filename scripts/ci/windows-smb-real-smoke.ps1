$ErrorActionPreference = 'Stop'

$shareName = "naos-ci-$PID"
$root = Join-Path $env:RUNNER_TEMP $shareName
$marker = "Managed by naos:ci-smoke"
$download = Join-Path $env:RUNNER_TEMP "$shareName-downloaded.txt"
$server = Get-Service -Name LanmanServer
if ($server.Status -ne 'Running') {
    Start-Service -Name LanmanServer
    $server.WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
}

New-Item -ItemType Directory -Path $root -Force | Out-Null
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

try {
    New-SmbShare -Name $shareName -Path $root -Description $marker -FolderEnumerationMode AccessBased -CachingMode None -FullAccess $current | Out-Null
    $share = Get-SmbShare -Name $shareName
    if ($share.Description -ne $marker -or $share.Path -ne $root) {
        throw "Windows SMB share metadata verification failed"
    }

    $remote = "\\localhost\$shareName"
    $source = Join-Path $root "source.txt"
    Set-Content -LiteralPath $source -Value "hello from naos windows smb smoke"
    $viaSmb = Join-Path $remote "via-smb.txt"
    Copy-Item -LiteralPath $source -Destination $viaSmb
    Copy-Item -LiteralPath $viaSmb -Destination $download
    if ((Get-Content -Raw $download).Trim() -ne "hello from naos windows smb smoke") {
        throw "Windows SMB read/write verification failed"
    }

    Rename-Item -LiteralPath $viaSmb -NewName "renamed.txt"
    $renamed = Join-Path $remote "renamed.txt"
    Remove-Item -LiteralPath $renamed
    if (Test-Path -LiteralPath (Join-Path $root "renamed.txt")) {
        throw "Windows SMB delete verification failed"
    }

    Write-Host "real Windows SMB read/write/rename/delete smoke test passed"
}
finally {
    if (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue) {
        Remove-SmbShare -Name $shareName -Force -Confirm:$false
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
}
