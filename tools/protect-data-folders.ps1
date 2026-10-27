<#
.SYNOPSIS
    Restrict the client-data folders to you, and check that they are.

.DESCRIPTION
    Snapshots, call trails, findings, reports and Prowler's raw results are
    written by containers onto Docker Desktop bind mounts, where the container
    cannot set file permissions. On Windows the folder's access list is the
    control, so this sets it: you, SYSTEM and Administrators only, inheritance
    from the drive removed, and every file inside reset to inherit just that.
    Files the containers write later inherit it too.

    Then it reads the access lists back and fails if anyone else can still
    get in, so "restricted" is checked rather than assumed.

    run-all.ps1 runs this before collecting. Run it yourself before using
    `docker compose run` directly:
        .\tools\protect-data-folders.ps1

.PARAMETER Folders
    Default: snapshots, output, prowler-output and evidence, beside this script's parent.

.PARAMETER KeyFiles
    Private keys to check (run-all.ps1 passes ICP_HOST_KEY_FILE and
    ICP_HOST_M365_KEY_FILE). Checked only, never changed: a key readable by
    anyone but you, SYSTEM and Administrators fails the run, with the command
    that fixes it. Inside the container the key shows as mode 0777 whatever
    its real access, so this is the only place it can be checked.
#>
param(
    [string[]]$Folders = @("snapshots", "output", "prowler-output", "evidence"),
    [string[]]$KeyFiles = @()
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$allowed = @($me.User.Value, "S-1-5-18", "S-1-5-32-544")   # you, SYSTEM, Administrators

function Get-OutsiderRules([string]$path) {
    # Each entry that lets in someone other than you, SYSTEM or Administrators,
    # as @{ Name; Sid }. Explicit and inherited alike.
    $acl = Get-Acl -LiteralPath $path
    $outsiders = @()
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne "Allow") { continue }
        try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $sid = "$($rule.IdentityReference)" }
        if ($allowed -notcontains $sid) { $outsiders += @{ Name = "$($rule.IdentityReference)"; Sid = $sid } }
    }
    return $outsiders
}

function Get-Outsiders([string]$path) {
    return @(Get-OutsiderRules $path | ForEach-Object { $_.Name })
}

$problems = @()
foreach ($name in $Folders) {
    $path = Join-Path $root $name
    New-Item -ItemType Directory -Force -Path $path | Out-Null

    # The folder: only these three, inherited by everything created inside.
    & icacls $path /inheritance:r /grant:r "$($me.Name):(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { $problems += "${name}: could not set its access list (icacls exit $LASTEXITCODE)"; continue }
    # What is already inside: drop any extra entries, inherit from the folder.
    if (Get-ChildItem -LiteralPath $path -Force | Select-Object -First 1) {
        & icacls (Join-Path $path "*") /reset /T /C /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { $problems += "${name}: could not reset the files inside (icacls exit $LASTEXITCODE)" }
    }

    # Checked, not assumed.
    if (-not (Get-Acl -LiteralPath $path).AreAccessRulesProtected) { $problems += "${name}: still inherits from the drive" }
    $items = @(Get-Item -LiteralPath $path) + @(Get-ChildItem -LiteralPath $path -Recurse -Force)
    foreach ($item in $items) {
        $outsiders = Get-Outsiders $item.FullName
        if ($outsiders) { $problems += "$($item.FullName): also open to $($outsiders -join ', ')" }
    }
    Write-Host ("  {0,-15} restricted to you, SYSTEM and Administrators ({1} files checked)" -f $name, ($items.Count - 1))
}

foreach ($key in $KeyFiles) {
    if (-not $key) { continue }
    if (-not (Test-Path -LiteralPath $key -PathType Leaf)) { $problems += "${key}: key file not found"; continue }
    $outsiders = @(Get-OutsiderRules $key)
    if ($outsiders) {
        # /inheritance:r drops inherited entries only; /remove:g drops the explicit
        # ones found here (seen live: Users and Authenticated Users set on the key itself).
        $remove = ($outsiders | ForEach-Object { "`"*$($_.Sid)`"" } | Select-Object -Unique) -join " "
        $problems += "${key}: private key also open to $(($outsiders | ForEach-Object { $_.Name }) -join ', '). Fix (you keep read access):`n" +
            "      icacls `"$key`" /inheritance:r /grant:r `"$($me.Name):R`" `"*S-1-5-18:F`" `"*S-1-5-32-544:F`"`n" +
            "      icacls `"$key`" /remove:g $remove"
        continue
    }
    Write-Host ("  {0,-15} readable only by you, SYSTEM and Administrators" -f (Split-Path -Leaf $key))
}

if ($problems) {
    Write-Host "Client-data folders or keys are not restricted:" -ForegroundColor Red
    $problems | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}
