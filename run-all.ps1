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

# Prowler draws its progress bar and tables in UTF-8; Windows PowerShell 5.1
# reads piped output in the old console codepage and garbles them.
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

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

# Docker Compose prefers a variable already set in this terminal over .env.
# Seen live: a VS Code terminal opened before the AWS key was replaced kept the
# old key, and every scan failed with "InvalidClientTokenId" although .env was
# right. For this script's run only, .env wins; values are never printed.
foreach ($name in $settings.Keys) {
    $inTerminal = [Environment]::GetEnvironmentVariable($name, "Process")
    if ($inTerminal -and $inTerminal -ne $settings[$name]) {
        Write-Host "Note: this terminal had a different $name than .env; using the value in .env." -ForegroundColor Yellow
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
}

function Step([string]$title, [string[]]$compose) {
    Write-Host ""
    Write-Host "== $title ==" -ForegroundColor Cyan
    # Docker writes progress to stderr, which Windows PowerShell 5.1 turns into
    # errors when output is captured; success is judged by the exit code only.
    $ErrorActionPreference = "Continue"
    if ($compose[0] -ne "prowler") {
        & docker compose run --rm @compose
        return ($LASTEXITCODE -eq 0)
    }
    # Prowler prints every read AWS refused (an organization policy, say) as a
    # red ERROR line. They are expected, are kept in Prowler's log file, and
    # collect-aws reports them; on screen, one line says how many there were.
    $refused = 0
    & docker compose run --rm @compose 2>&1 | ForEach-Object {
        # A line from the error stream arrives as an ErrorRecord: take its text.
        # A blank one would otherwise print as "System.Management.Automation.RemoteException".
        $line = if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" }
        if ($line -eq "System.Management.Automation.RemoteException") { $line = "" }
        if ($line -match "is not authorized to perform: ") { $refused++ }
        elseif ($line.Trim() -ne "") { Write-Host $line }
    }
    $code = $LASTEXITCODE
    if ($refused) {
        Write-Host "  ($refused reads were refused by AWS, most likely by an organization policy; the import step lists them and the report marks those checks as not assessed)" -ForegroundColor Yellow
    }
    return ($code -eq 0)
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
    # Prowler appends to an existing results file, so leftovers from an
    # interrupted run would make this one unreadable. Start clean.
    Remove-Item -Force -ErrorAction SilentlyContinue "prowler-output/prowler.ocsf.json", "prowler-output/prowler.log"
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
