# Dot-sourced by every script: . "$PSScriptRoot\env.ps1"
$env:AWS_ENDPOINT_URL      = "http://localhost:4566"
$env:AWS_DEFAULT_REGION    = "us-east-1"
$env:AWS_ACCESS_KEY_ID     = "test"
$env:AWS_SECRET_ACCESS_KEY = "test"
$env:AWS_PAGER             = ""     # stop the CLI pausing at "-- More --"

$Root  = $PSScriptRoot
$Work  = Join-Path $Root "work"                 # generated files + reports
$Venv  = Join-Path $Root ".venv"                # python venv holding boto3
$Py    = Join-Path $Venv "Scripts\python.exe"
$Prefix = "sec-lab"                             # scanner only touches resources starting with this

$Bucket   = "sec-lab-data"
$Role     = "sec-lab-app-role"
$Topic    = "sec-lab-alerts"
$Queue    = "sec-lab-alert-inbox"
$LogGroup = "/sec-lab/scanner"
$Alarm    = "sec-lab-high-findings"
New-Item -ItemType Directory -Force $Work | Out-Null

function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Must($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE) - see the output above." } }
function RequireTool($name, $hint) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "$name not found. $hint" }
}
function RequireAws { RequireTool aws "Run: winget install -e --id Amazon.AWSCLI  then open a NEW PowerShell window." }
function RequireFloci {
    aws sts get-caller-identity --query Account --output text *> $null
    if ($LASTEXITCODE -ne 0) { throw "Cannot reach Floci at $env:AWS_ENDPOINT_URL. Run .\01-start-floci.ps1 first (Docker Desktop must be running)." }
}
function WriteJson($path, $text) { [IO.File]::WriteAllText($path, $text) }   # no BOM, unlike Set-Content in PS 5.1
function EnsureVenv {
    if (-not (Test-Path $Py)) {
        RequireTool python "Install Python 3 (winget install -e --id Python.Python.3.12)."
        python -m venv $Venv; Must "python -m venv"
    }
    & $Py -c "import boto3" *> $null
    if ($LASTEXITCODE -ne 0) { & $Py -m pip install -q boto3; Must "pip install boto3" }
}
