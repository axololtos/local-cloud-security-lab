# Alert plumbing: scanner -> CloudWatch Logs -> metric filter -> alarm -> SNS -> SQS "inbox" (stands in for email).
. "$PSScriptRoot\env.ps1"
RequireAws; RequireFloci

Step "SQS inbox + SNS topic + subscription"
$qUrl = aws sqs create-queue --queue-name $Queue --query QueueUrl --output text; Must "sqs create-queue"
$qArn = aws sqs get-queue-attributes --queue-url $qUrl --attribute-names QueueArn --query Attributes.QueueArn --output text; Must "get-queue-attributes"
$tArn = aws sns create-topic --name $Topic --query TopicArn --output text; Must "sns create-topic"
aws sns subscribe --topic-arn $tArn --protocol sqs --notification-endpoint $qArn --query SubscriptionArn --output text; Must "sns subscribe"
WriteJson (Join-Path $Work "alert-arns.txt") "$tArn`n$qUrl`n"

Step "Log group + metric filter (counts SECFINDING_HIGH log lines)"
aws logs create-log-group --log-group-name $LogGroup
aws logs put-metric-filter --log-group-name $LogGroup --filter-name high-findings --filter-pattern SECFINDING_HIGH `
    --metric-transformations "metricName=HighFindings,metricNamespace=SecLab,metricValue=1"; Must "put-metric-filter"

Step "Alarm: >=1 HIGH finding in a minute -> notify the SNS topic"
aws cloudwatch put-metric-alarm --alarm-name $Alarm --namespace SecLab --metric-name HighFindings --statistic Sum `
    --period 60 --evaluation-periods 1 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold `
    --treat-missing-data notBreaching --alarm-actions $tArn; Must "put-metric-alarm"

Write-Host "`nAlerting wired. Topic: $tArn" -ForegroundColor Green
Write-Host "Next: .\06-drift-alert.ps1  (re-breaks the bucket, scans, and shows the alert arriving)"
