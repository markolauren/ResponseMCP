# Deploy Response MCP Server Infrastructure to Azure
# This script sets up all Azure resources (one-time setup)

param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,
    
    [Parameter(Mandatory=$true)]
    [string]$Location,
    
    [Parameter(Mandatory=$true)]
    [string]$DefenderClientId,
    
    [Parameter(Mandatory=$true)]
    [SecureString]$DefenderClientSecret,
    
    [Parameter(Mandatory=$true)]
    [string]$DefenderTenantId,
    
    [Parameter(Mandatory=$false)]
    [SecureString]$McpApiKey
)

$ErrorActionPreference = "Stop"

# Verify Azure CLI login and show current subscription
Write-Host "Checking Azure CLI login..." -ForegroundColor Yellow
$subscription = az account show --query "{name:name, id:id}" -o json | ConvertFrom-Json
if (-not $subscription) {
    Write-Error "Not logged in to Azure CLI. Please run 'az login' first."
    exit 1
}
Write-Host "  Using subscription: $($subscription.name) ($($subscription.id))" -ForegroundColor Green
Write-Host ""

# Convert SecureString to plain text for Bicep (only in memory)
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($DefenderClientSecret)
$clientSecretPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# Generate or convert MCP API Key
if (-not $McpApiKey) {
    Write-Host "Generating MCP API key..." -ForegroundColor Yellow
    $apiKeyPlainText = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
} else {
    Write-Host "Using provided MCP API key..." -ForegroundColor Yellow
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($McpApiKey)
    $apiKeyPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Response MCP - Infrastructure Deploy     " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroup" -ForegroundColor Cyan
Write-Host "Location:       $Location" -ForegroundColor Cyan
Write-Host ""

# Step 1: Create Resource Group (if it doesn't exist)
Write-Host "Step 1: Ensuring resource group exists..." -ForegroundColor Yellow
$rgExists = az group exists --name $ResourceGroup
if ($rgExists -eq "false") {
    Write-Host "  Creating resource group '$ResourceGroup'..." -ForegroundColor Gray
    az group create --name $ResourceGroup --location $Location --output none
    Write-Host "  Resource group created!" -ForegroundColor Green
} else {
    Write-Host "  Resource group '$ResourceGroup' already exists" -ForegroundColor Green
}

# Step 2: Deploy Infrastructure with Bicep
Write-Host ""
Write-Host "Step 2: Deploying infrastructure (Bicep)..." -ForegroundColor Yellow

$bicepFile = Join-Path $PSScriptRoot "main.bicep"

# Ensure Bicep CLI is installed and up to date
# If you get "[WinError 193] %1 is not a valid Win32 application", fix with:
#   Remove-Item "$env:USERPROFILE\.azure\bin\bicep.exe" -Force
#   az bicep install
Write-Host "  Checking Bicep installation..." -ForegroundColor Gray
az bicep install 2>&1 | Out-Null
az bicep upgrade 2>&1 | Out-Null

$deployment = az deployment group create `
    --resource-group $ResourceGroup `
    --template-file $bicepFile `
    --parameters `
        defenderClientId=$DefenderClientId `
        defenderClientSecret=$clientSecretPlainText `
        defenderTenantId=$DefenderTenantId `
        mcpApiKey=$apiKeyPlainText `
    --query "properties.outputs" `
    -o json | ConvertFrom-Json

$acrName = $deployment.acrName.value
$acrLoginServer = $deployment.acrLoginServer.value
$containerAppUrl = $deployment.containerAppUrl.value
$sseEndpoint = $deployment.sseEndpoint.value
$containerAppName = $deployment.containerAppName.value

Write-Host "  Infrastructure deployed!" -ForegroundColor Green

# Done!
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "    INFRASTRUCTURE DEPLOYMENT COMPLETE!    " -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Resources created:" -ForegroundColor Yellow
Write-Host "  Container Registry:     $acrLoginServer" -ForegroundColor Cyan
Write-Host "  Container App:          $containerAppName" -ForegroundColor Cyan
Write-Host "  Container App URL:      $containerAppUrl" -ForegroundColor Cyan
Write-Host "  SSE Endpoint:           $sseEndpoint" -ForegroundColor Cyan
Write-Host ""
Write-Host "=== IMPORTANT: Save this MCP API Key ==="-ForegroundColor Yellow
Write-Host "  MCP API Key: $apiKeyPlainText" -ForegroundColor Green
Write-Host "  (This key won't be shown again!)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Build and deploy your container:" -ForegroundColor Gray
Write-Host "     .\infra\deploy-container.ps1 -ResourceGroup $ResourceGroup" -ForegroundColor White
Write-Host ""
Write-Host "  2. Update VS Code mcp.json:" -ForegroundColor Gray
Write-Host @"
     {
         "mcpServers": {
             "Response MCP": {
                 "type": "sse",
                 "url": "$sseEndpoint",
                 "headers": {
                     "X-API-Key": "$apiKeyPlainText"
                 }
             }
         }
     }
"@ -ForegroundColor White
Write-Host ""
