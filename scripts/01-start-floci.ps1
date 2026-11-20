. "$PSScriptRoot\env.ps1"
RequireAws
RequireTool docker "Install/start Docker Desktop."

Step "Start Floci (skipped if something already serves port 4566, e.g. your 'axo' compose)"
docker info *> $null
if ($LASTEXITCODE -ne 0) { throw "Docker daemon is not running. Start Docker Desktop and wait until it says 'Engine running'." }
$existing = docker ps --filter "publish=4566" --format "{{.Names}}"
if ($existing) {
    Write-Host "Already running: $existing - reusing it."
} else {
    docker compose -f "$Root\compose.yaml" up -d; Must "docker compose up"
    Start-Sleep 5
}

Step "Check CLI -> Floci (expect account 000000000000)"
aws sts get-caller-identity; Must "sts get-caller-identity"
Write-Host "`nSuccess = an Account/Arn is printed above."
Write-Host "Note: Floci is in-memory by default. If the container restarts, re-run from 02."
