# Rebuild the environment as code (secure by default), then prove it with the same scanner.
. "$PSScriptRoot\env.ps1"
RequireAws; RequireTool terraform "Install: winget install -e --id Hashicorp.Terraform"
RequireFloci
EnsureVenv
$tf = Join-Path $Root "terraform"

Step "terraform init + apply (against Floci)"
terraform "-chdir=$tf" init -input=false; Must "terraform init"
terraform "-chdir=$tf" apply -auto-approve -input=false; Must "terraform apply"

Step "Scan only the Terraform-built resources (prefix sec-lab-tf) - expect 0 findings"
& $Py "$Root\scanner\scanner.py" --prefix "sec-lab-tf" --report "$Work\report-terraform.json"
if ($LASTEXITCODE -eq 0) { Write-Host "`nTerraform build is clean." -ForegroundColor Green }
elseif ($LASTEXITCODE -eq 1) { Write-Host "`nFindings in the Terraform build - see above (could be a Floci gap, see README)." -ForegroundColor Yellow }
else { throw "scanner crashed (exit $LASTEXITCODE)." }
