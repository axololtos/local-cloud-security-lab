# Removes only what this lab created (does NOT stop Floci - your 'axo' compose may be using it).
param([switch]$StopFloci)   # -StopFloci also runs 'docker compose down' for THIS folder's compose.yaml
. "$PSScriptRoot\env.ps1"
RequireAws; RequireFloci
$tf = Join-Path $Root "terraform"

Step "Terraform destroy"
if (Test-Path "$tf\terraform.tfstate") { terraform "-chdir=$tf" destroy -auto-approve -input=false }

Step "Delete baseline bucket, role, alerting"
# Versioning is on after the fix, so 'rb --force' alone leaves versions/delete markers behind: purge them first.
EnsureVenv
& $Py -c "import boto3,os,sys; s=boto3.resource('s3',endpoint_url=os.environ['AWS_ENDPOINT_URL']).Bucket(sys.argv[1]); s.object_versions.delete(); print('purged all versions')" $Bucket
aws s3 rb "s3://$Bucket" --force
aws iam delete-role-policy --role-name $Role --policy-name allow-everything
aws iam delete-role --role-name $Role
aws cloudwatch delete-alarms --alarm-names $Alarm
aws logs delete-log-group --log-group-name $LogGroup
$arns = if (Test-Path "$Work\alert-arns.txt") { Get-Content "$Work\alert-arns.txt" } else { @() }
if ($arns.Count -ge 2) { aws sns delete-topic --topic-arn $arns[0]; aws sqs delete-queue --queue-url $arns[1] }

if ($StopFloci) { Step "Stop Floci"; docker compose -f "$Root\compose.yaml" down }
Write-Host "`nDone. Delete work\ , .venv\ and terraform\.terraform* to reset local files." -ForegroundColor Green
