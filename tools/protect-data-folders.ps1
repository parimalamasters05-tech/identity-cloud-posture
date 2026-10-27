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
#>
param(
    [string[]]$Folders = @("snapshots", "output", "prowler-output", "evidence")
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$allowed = @($me.User.Value, "S-1-5-18", "S-1-5-32-544")   # you, SYSTEM, Administrators

function Get-Outsiders([string]$path) {
    $acl = Get-Acl -LiteralPath $path
    $outsiders = @()
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne "Allow") { continue }
        try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $sid = "$($rule.IdentityReference)" }
        if ($allowed -notcontains $sid) { $outsiders += "$($rule.IdentityReference)" }
    }
    return $outsiders
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

if ($problems) {
    Write-Host "Client-data folders are not restricted:" -ForegroundColor Red
    $problems | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}
