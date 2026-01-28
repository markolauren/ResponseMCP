# Deploy Response MCP Server Container to Azure
# This script builds and deploys the container image (frequent updates)

param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup
)

$ErrorActionPreference = "Stop"

# Verify Azure CLI login
Write-Host "Checking Azure CLI login..." -ForegroundColor Yellow
$subscription = az account show --query "{name:name, id:id}" -o json | ConvertFrom-Json
if (-not $subscription) {
    Write-Error "Not logged in to Azure CLI. Please run 'az login' first."
    exit 1
}
Write-Host "  Using subscription: $($subscription.name) ($($subscription.id))" -ForegroundColor Green
Write-Host ""

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Response MCP - Container Deploy          " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroup" -ForegroundColor Cyan
Write-Host ""

# Step 1: Get existing resources
Write-Host "Step 1: Looking up Azure resources..." -ForegroundColor Yellow

$acr = az acr list --resource-group $ResourceGroup --query "[0]" -o json | ConvertFrom-Json
if (-not $acr) {
    Write-Error "No Container Registry found in resource group '$ResourceGroup'. Run deploy-infrastructure.ps1 first."
    exit 1
}
$acrName = $acr.name
$acrLoginServer = $acr.loginServer

$app = az containerapp list --resource-group $ResourceGroup --query "[0]" -o json | ConvertFrom-Json
if (-not $app) {
    Write-Error "No Container App found in resource group '$ResourceGroup'. Run deploy-infrastructure.ps1 first."
    exit 1
}
$appName = $app.name
$containerAppUrl = "https://$($app.properties.configuration.ingress.fqdn)"
$sseEndpoint = "$containerAppUrl/sse"

Write-Host "  ACR:  $acrLoginServer" -ForegroundColor Gray
Write-Host "  App:  $appName" -ForegroundColor Gray

# Step 2: Build and Push Docker Image
Write-Host ""
Write-Host "Step 2: Building Docker image in Azure (cloud build)..." -ForegroundColor Yellow
Write-Host "  Note: Build happens in Azure Container Registry - local Docker not required" -ForegroundColor Gray
Write-Host "  This may take a few minutes (suppressing build logs to avoid encoding issues)..." -ForegroundColor Gray

# Build and push using ACR Tasks (cloud build - no local Docker needed)
$dockerContext = Join-Path $PSScriptRoot ".."

# Temporarily allow warnings/info messages without stopping
$prevErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Continue"

# Suppress log streaming to avoid Unicode encoding issues on PowerShell 5
az acr build `
    --registry $acrName `
    --image response-mcp:latest `
    --file "$dockerContext/Dockerfile" `
    --platform linux/amd64 `
    --no-logs `
    $dockerContext

$ErrorActionPreference = $prevErrorAction

if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker image build failed"
    exit 1
}

Write-Host "  Image built and pushed!" -ForegroundColor Green

# Step 3: Update Container App with new image
Write-Host ""
Write-Host "Step 3: Updating container app with new revision..." -ForegroundColor Yellow

# Generate unique revision suffix (timestamp)
$revisionSuffix = (Get-Date -Format "yyyyMMdd-HHmmss").ToLower()

az containerapp update `
    --name $appName `
    --resource-group $ResourceGroup `
    --image "$acrLoginServer/response-mcp:latest" `
    --revision-suffix $revisionSuffix `
    --output none

Write-Host "  New revision deployed: $revisionSuffix" -ForegroundColor Green

# Done!
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "      CONTAINER DEPLOYMENT COMPLETE!       " -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Container App URL: $containerAppUrl" -ForegroundColor Yellow
Write-Host "SSE Endpoint:      $sseEndpoint" -ForegroundColor Yellow
Write-Host "Health Check:      $containerAppUrl/health" -ForegroundColor Yellow
Write-Host ""

# Check IP restrictions
Write-Host "IP Restrictions:" -ForegroundColor Yellow
$ipRestrictions = az containerapp ingress access-restriction list `
    --name $appName `
    --resource-group $ResourceGroup `
    --query "[?action=='Allow']" `
    -o json | ConvertFrom-Json

if ($ipRestrictions -and $ipRestrictions.Count -gt 0) {
    Write-Host "  Access is restricted to the following IPs:" -ForegroundColor Cyan
    foreach ($restriction in $ipRestrictions) {
        Write-Host "    - $($restriction.ipAddressRange) ($($restriction.name))" -ForegroundColor White
    }
} else {
    Write-Host "  No IP restrictions - accessible from anywhere" -ForegroundColor Red
    Write-Host ""
    Write-Host "  To restrict access to specific IPs, run:" -ForegroundColor Gray
    Write-Host "  az containerapp ingress access-restriction set --name $appName --resource-group $ResourceGroup --rule-name <rule-name> --ip-address <ip-address> --action Allow" -ForegroundColor White
    Write-Host ""
    Write-Host "  Examples:" -ForegroundColor Gray
    Write-Host "  az containerapp ingress access-restriction set --name $appName --resource-group $ResourceGroup --rule-name AllowOfficeIP --ip-address 203.0.113.10/32 --action Allow" -ForegroundColor White
    Write-Host "  az containerapp ingress access-restriction set --name $appName --resource-group $ResourceGroup --rule-name AllowHomeIP --ip-address 198.51.100.5/32 --action Allow" -ForegroundColor White
    Write-Host ""
    Write-Host "  Tip: Use unique rule names to add multiple IP addresses" -ForegroundColor Gray
}

Write-Host ""
Write-Host "The new version is now live!" -ForegroundColor Green
Write-Host ""
