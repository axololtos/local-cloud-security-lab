# Simulates configuration drift (someone re-opens the bucket), scans with alerting on, shows the alert.
. "$PSScriptRoot\env.ps1"
RequireAws; RequireFloci
EnsureVenv
$arns = Get-Content (Join-Path $Work "alert-arns.txt")
if ($arns.Count -lt 2) { throw "Run .\05-alerting.ps1 first." }
$tArn = $arns[0]; $qUrl = $arns[1]

Step "Drift: re-run the baseline (re-opens the bucket + wildcard role)"
& "$PSScriptRoot\02-baseline.ps1" | Out-Null

Step "Drain old messages from the inbox"
aws sqs purge-queue --queue-url $qUrl

Step "Scan with alerting (SNS + CloudWatch Logs)"
& $Py "$Root\scanner\scanner.py" --prefix $Prefix --sns-topic-arn $tArn --log-group $LogGroup --report "$Work\report-drift.json"

Step "Alert delivered to the SQS inbox (SNS -> SQS)"
aws sqs receive-message --queue-url $qUrl --wait-time-seconds 5 --max-number-of-messages 1 --query "Messages[0].Body" --output text

Step "Metric + alarm state (alarm evaluates on a 60s period; re-run this check after ~1-2 min)"
Start-Sleep 3
aws cloudwatch describe-alarms --alarm-names $Alarm --query "MetricAlarms[0].[AlarmName,StateValue,StateReason]" --output text
aws logs filter-log-events --log-group-name $LogGroup --filter-pattern SECFINDING_HIGH --query "events[].message" --output text
Write-Host "`nClean up the drift with: .\04-fix.ps1" -ForegroundColor Yellow
