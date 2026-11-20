# Builds a deliberately MISCONFIGURED environment (the "before" picture) for the scanner to find.
# Everything is fake demo data on your local emulator - no real AWS account is touched.
. "$PSScriptRoot\env.ps1"
RequireAws; RequireFloci

Step "Bucket $Bucket"
aws s3api create-bucket --bucket $Bucket

Step "Misconfig 1/4: remove Block Public Access"
aws s3api delete-public-access-block --bucket $Bucket

Step "Misconfig 2/4: public-read bucket policy (wildcard principal)"
$policy = '{"Version":"2012-10-17","Statement":[{"Sid":"PublicRead","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::' + $Bucket + '/*"}]}'
$pf = Join-Path $Work "public-policy.json"; WriteJson $pf $policy
aws s3api put-bucket-policy --bucket $Bucket --policy "file://$pf"; Must "put-bucket-policy"

Step "Misconfig 3/4: unversioned bucket, SSE-S3 only (no KMS key), holding a fake secret file"
WriteJson (Join-Path $Work "secret-information.txt") "FAKE-DEMO-SECRET: db_password=not-a-real-password`n"
aws s3 cp (Join-Path $Work "secret-information.txt") "s3://$Bucket/secret-information.txt"; Must "s3 cp"

Step "Misconfig 4/4: IAM role that allows Action * on Resource *"
$trust = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
$tp = Join-Path $Work "trust-ec2.json"; WriteJson $tp $trust
aws iam get-role --role-name $Role *> $null
if ($LASTEXITCODE -ne 0) {
    aws iam create-role --role-name $Role --assume-role-policy-document "file://$tp" --query Role.Arn --output text; Must "create-role"
} else { Write-Host "Role $Role already exists - re-applying its wildcard policy." }
$wild = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
$wf = Join-Path $Work "wildcard-policy.json"; WriteJson $wf $wild
aws iam put-role-policy --role-name $Role --policy-name allow-everything --policy-document "file://$wf"; Must "put-role-policy"

Write-Host "`nBaseline ready. Expected scanner findings next: public policy, no Block Public Access, no KMS encryption, no versioning, IAM wildcard (5 on a fresh run; 3 when re-run after a fix, because KMS encryption and versioning stay on)." -ForegroundColor Green
