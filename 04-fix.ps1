. "$PSScriptRoot\env.ps1"
RequireAws; RequireFloci
EnsureVenv

Step "KMS key + alias/sec-lab (reused if it exists)"
$existing = aws kms list-aliases --query "Aliases[?AliasName=='alias/sec-lab'].AliasName" --output text
if (-not $existing) {
    $keyId = aws kms create-key --description "sec-lab bucket encryption" --query KeyMetadata.KeyId --output text; Must "kms create-key"
    aws kms create-alias --alias-name alias/sec-lab --target-key-id $keyId; Must "kms create-alias"
}

Step "Scan, remediate, re-scan"
& $Py "$Root\scanner\scanner.py" --prefix $Prefix --fix --kms-key-id alias/sec-lab --report "$Work\report-after.json"
if ($LASTEXITCODE -eq 0) { Write-Host "`nAll findings remediated." -ForegroundColor Green }
elseif ($LASTEXITCODE -eq 1) { Write-Host "`nSome findings remain - see the AFTER list and README limitations." -ForegroundColor Yellow }
else { throw "scanner crashed (exit $LASTEXITCODE)." }
