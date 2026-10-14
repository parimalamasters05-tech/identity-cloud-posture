<#
.SYNOPSIS
    One command for a mixed-platform client: collect every configured
    platform, then produce one combined report (the brief, week 5).

.DESCRIPTION
    Reads .env to see which platforms are set up, then for each:
      Google Workspace  collect            (if ICP_TENANT_ID and ICP_HOST_KEY_FILE are set)
      Microsoft 365     collect-m365       (if ICP_M365_TENANT_ID is set)
      AWS               prowler, collect-aws (if ICP_AWS_ROLE_ARN is set)
    Every step is read-only. A platform whose collection fails is not fatal:
    the report then uses that platform's newest saved snapshot, whose capture
    date is printed on the cover.

    Finally: report --latest --with-progress, one report across every platform,
    each compared with its previous snapshot.

.PARAMETER Skip
    Platforms to leave out of collection: google, m365, aws.
    Example: .\run-all.ps1 -Skip google

.PARAMETER NoProgress
    Leave out the "Progress since the previous review" pages.
#>
param(
    [ValidateSet("google", "m365", "aws")]
    [string[]]$Skip = @(),
    [switch]$NoProgress
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if (-not (Test-Path ".env")) {
    Write-Host "No .env file here. Copy .env.example to .env and fill it in first." -ForegroundColor Red
    exit 1
}

# Names only: values are never printed.
$settings = @{}
foreach ($line in Get-Content ".env") {
    if ($line -match '^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$') {
        $settings[$Matches[1]] = $Matches[2].Trim().Trim('"').Trim("'")
    }
}
function IsSet([string]$name) { return $settings.ContainsKey($name) -and $settings[$name] -ne "" }

function Step([string]$title, [string[]]$compose) {
    Write-Host ""
    Write-Host "== $title ==" -ForegroundColor Cyan
    & docker compose run --rm @compose
    return ($LASTEXITCODE -eq 0)
}

$results = [ordered]@{}

if ($Skip -contains "google") { $results["Google Workspace"] = "skipped" }
elseif ((IsSet "ICP_TENANT_ID") -and (IsSet "ICP_HOST_KEY_FILE")) {
    $results["Google Workspace"] = if (Step "Google Workspace: collect" @("collect")) { "collected" } else { "FAILED - newest saved snapshot used" }
}
else { $results["Google Workspace"] = "not configured" }

if ($Skip -contains "m365") { $results["Microsoft 365"] = "skipped" }
elseif (IsSet "ICP_M365_TENANT_ID") {
    $results["Microsoft 365"] = if (Step "Microsoft 365: collect" @("collect-m365")) { "collected" } else { "FAILED - newest saved snapshot used" }
}
else { $results["Microsoft 365"] = "not configured" }

if ($Skip -contains "aws") { $results["AWS"] = "skipped" }
elseif (IsSet "ICP_AWS_ROLE_ARN") {
    $ok = Step "AWS: Prowler scan" @("prowler")
    if ($ok -and (Test-Path "prowler-output\prowler.ocsf.json")) {
        $ok = Step "AWS: import Prowler results" @("collect-aws")
    }
    else { $ok = $false }
    $results["AWS"] = if ($ok) { "collected" } else { "FAILED - newest saved snapshot used" }
}
else { $results["AWS"] = "not configured" }

$reportArgs = @("report", "report", "--latest")
if (-not $NoProgress) { $reportArgs += "--with-progress" }
$reported = Step "One report across every platform" $reportArgs

Write-Host ""
Write-Host "== Summary ==" -ForegroundColor Cyan
foreach ($platform in $results.Keys) {
    $state = $results[$platform]
    $colour = if ($state -like "FAILED*") { "Yellow" } else { "Gray" }
    Write-Host ("  {0,-17} {1}" -f $platform, $state) -ForegroundColor $colour
}
if (-not $reported) {
    Write-Host "The report step failed; see the messages above." -ForegroundColor Red
    exit 1
}
Write-Host "Report written to the output folder (newest *__combined__*.pdf, or a single-platform PDF)." -ForegroundColor Green
