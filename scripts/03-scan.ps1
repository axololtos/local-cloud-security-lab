# Report-only scan (changes nothing). Exit code of the scanner is 1 when findings exist - that is expected here.
. "$PSScriptRoot\env.ps1"
RequireAws; RequireFloci
Step "Python venv + boto3 (first run only)"
EnsureVenv

Step "Scan resources starting with '$Prefix' (read-only)"
& $Py "$Root\scanner\scanner.py" --prefix $Prefix --report "$Work\report-before.json"
if ($LASTEXITCODE -eq 1) { Write-Host "`nFindings found, as expected on the baseline. Next: .\04-fix.ps1" -ForegroundColor Yellow }
elseif ($LASTEXITCODE -ne 0) { throw "scanner crashed (exit $LASTEXITCODE) - see output above." }
else { Write-Host "`nNo findings." -ForegroundColor Green }
