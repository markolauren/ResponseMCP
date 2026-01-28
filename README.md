# Response MCP Server

A Model Context Protocol (MCP) server that enables agentic SecOps using orchestrators like VS Code with GitHub Copilot to execute Microsoft Defender XDR response actions. Deployed to Azure Container Apps for secure, authenticated, cloud-based access.

## Overview

This MCP server exposes Microsoft Defender XDR capabilities as tools for agentic SecOps workflows. Security analysts use natural language through orchestrators like GitHub Copilot to manage incidents, isolate compromised devices, run antivirus scans, collect forensic packages, and execute incident response actions. 

[Showcase - https://markolauren.github.io/ResponseMCP/response-mcp-showcase.html](https://markolauren.github.io/ResponseMCP/response-mcp-showcase.html)

### Works in Tandem with Sentinel MCP

This Response MCP server works in tandem with the [Sentinel MCP server](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-get-started) to provide a complete agentic SecOps workflow:

- **Sentinel MCP**: Data exploration and threat triage
  - Query security logs with KQL
  - Investigate alerts and run hunting queries
  - Analyze attack patterns and indicators
  - Entity analysis
  
- **Response MCP** (this server): Incident response and remediation
  - Execute device response actions (isolate, restrict, quarantine)
  - Take identity response actions (disable accounts, reset passwords)
  - Manage incidents (classify, assign, comment)

Together, they enable end-to-end incident response: from detection and triage to containment and remediation, all through natural language interactions and agentic orchestration.

**Example interactions:**
- "Check the status of device WORKSTATION-01"
- "Isolate the compromised laptop immediately"
- "Run a full antivirus scan on the server"
- "Show me recent response actions on this device"

## Architecture

```
┌─────────────────┐                ┌──────────────────────┐
│   VS Code +     │────SSE────────▶│  Azure Container App │
│  GitHub Copilot │  X-API-Key     │  (Response MCP)      │
└─────────────────┘  Authentication└──────────────────────┘
                                             │
                                             │ Client Credentials
                                             │ (Service Principal)
                                             │
                         ┌───────────────────┴───────────────────┐
                         ▼                                       ▼
          ┌─────────────────────────────┐     ┌─────────────────────────────┐
          │  Microsoft Defender         │     │  Microsoft Graph API        │
          │  for Endpoint               │     │  - Incident management      │
          │  - Device response actions  │     │  - Identity actions (MDI)   │
          │  - Investigation packages   │     └─────────────────────────────┘
          └─────────────────────────────┘
```

**SSE (Server-Sent Events):** A web standard that maintains a persistent HTTP connection, allowing the MCP server to stream real-time responses back to the AI assistant.

## Available Tools

### Device Response Actions (Defender for Endpoint)

| Tool | Description |
|------|-------------|
| `echo` | Test server connectivity |
| `get_machine_by_name` | Find device by hostname |
| `get_machine_actions` | List response action history |
| `isolate_device` | Isolate device from network |
| `release_device` | Release device from isolation |
| `run_antivirus_scan` | Initiate Quick or Full AV scan |
| `stop_and_quarantine` | Stop process and quarantine file |
| `restrict_code_execution` | Block unsigned applications |
| `remove_code_restriction` | Remove code restrictions |
| `collect_investigation_package` | Collect forensic data |
| `get_investigation_package_uri` | Get download URL for investigation package |
| `isolate_multiple` | Bulk isolate multiple devices |

### Identity Response Actions (Defender for Identity)

| Tool | Description | Provider | Status |
|------|-------------|----------|--------|
| `disable_ad_account` | Disable Active Directory account | Active Directory | ✅ Available |
| `enable_ad_account` | Re-enable Active Directory account | Active Directory | ✅ Available |
| `force_ad_password_reset` | Force user to change password at next logon | Active Directory | ✅ Available |
| ~~`revoke_entra_sessions`~~ | Revoke all Entra ID sessions | Entra ID | ⏳ Not yet supported |
| ~~`require_entra_signin`~~ | Require Entra ID user to sign in again | Entra ID | ⏳ Not yet supported |
| ~~`mark_entra_user_compromised`~~ | Mark Entra ID user as compromised | Entra ID | ⏳ Not yet supported |

### Incident Management

| Tool | Description |
|------|-------------|
| `get_incident` | Get incident details by ID |
| `list_incidents` | List incidents with filtering |
| `update_incident_status` | Mark incident as active/resolved |
| `assign_incident` | Assign incident to analyst |
| `classify_incident` | Set classification (TP/FP) and determination |
| `add_incident_tags` | Add custom tags for categorization |
| `add_incident_comment` | Add investigation comments |

## Prerequisites

### 1. Entra ID App Registration

**Steps:**
1. Navigate to **Azure Portal** > **Entra ID** > **App Registrations** > **New registration**
   - Name: `Response MCP Server` (or your preferred name)
   - Supported account types: **Accounts in this organizational directory only**
   - Click **Register**
2. **Save these values** (needed for deployment):
   - **Application (client) ID**
   - **Directory (tenant) ID**
3. Create a **client secret**:
   - Go to **Certificates & secrets** > **New client secret**
   - Description: `Response MCP Secret`
   - Expires: Choose expiration period (e.g., 12 months)
   - Click **Add**
   - **Copy the secret value immediately** (shown only once)
4. Add **API permissions**:
   - Go to **API permissions** > **Add a permission**
   - Add the permissions listed below
   - **Grant admin consent** for all permissions

#### Required Permissions

**WindowsDefenderATP (Defender for Endpoint)**

| Permission | Type | Description |
|------------|------|-------------|
| `Machine.ReadWrite.All` | Application | Read machine actions and get investigation package URIs |
| `Machine.Isolate` | Application | Isolate/release machines |
| `Machine.Scan` | Application | Run antivirus scans |
| `Machine.StopAndQuarantine` | Application | Stop and quarantine files |
| `Machine.RestrictExecution` | Application | Restrict/unrestrict code execution |
| `Machine.CollectForensics` | Application | Collect investigation packages |

**Microsoft Graph API**

| Permission | Type | Description |
|------------|------|-------------|
| `Machine.ReadWrite.All` | Application | Read machine actions and get investigation package URIs |
| `Machine.Isolate` | Application | Isolate/release machines |
| `Machine.Scan` | Application | Run antivirus scans |
| `Machine.StopAndQuarantine` | Application | Stop and quarantine files |
| `Machine.RestrictExecution` | Application | Restrict/unrestrict code execution |
| `Machine.CollectForensics` | Application | Collect investigation packages |

#### Microsoft Graph API

| Permission | Type | Description |
|------------|------|-------------|
| `SecurityAlert.ReadWrite.All` | Application | Read and update security alerts |
| `SecurityIdentitiesAccount.Read.All` | Application | Read identity accounts from MDI |
| `SecurityIdentitiesActions.ReadWrite.All` | Application | Invoke actions on identity accounts |
| `SecurityIncident.ReadWrite.All` | Application | Read and update security incidents |
| `User.Read.All` | Application | Resolve UPNs to user IDs (optional) |

### 2. Azure Subscription

For deploying to Azure Container Apps.

**Azure Infrastructure:**

```
┌─────────────────────────────────────────────────────────────┐
│  Resource Group: response-mcp-rg                            │
│                                                             │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Container Apps Environment                        │     │
│  │  - Managed Kubernetes infrastructure               │     │
│  │  - Auto-scaling (min: 0, max: 3 replicas)          │     │
│  │                                                    │     │
│  │  ┌──────────────────────────────────────────┐      │     │
│  │  │  Container App: response-mcp             │      │     │
│  │  │  - SSE endpoint on port 8000             │      │     │
│  │  │  - API key authentication                │      │     │
│  │  │  - Environment secrets (Defender creds)  │      │     │
│  │  │  - HTTPS ingress                         │      │     │
│  │  └──────────────────────────────────────────┘      │     │
│  │                                                    │     │
│  └────────────────────────────────────────────────────┘     │
│                                                             │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Azure Container Registry (Basic)                  │     │
│  │  - Stores Docker images                            │     │
│  │  - ACR Tasks for cloud builds                      │     │
│  └────────────────────────────────────────────────────┘     │
│                                                             │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Log Analytics Workspace                           │     │
│  │  - Container App logs                              │     │
│  │  - Request/response tracing                        │     │
│  │  - 30-day retention                                │     │
│  └────────────────────────────────────────────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Deployment to Azure Container Apps

### Prerequisites

- **Azure CLI** (v2.20.0+) - [Install](https://aka.ms/installazurecliwindows) or `winget install Microsoft.AzureCLI`
- **Bicep** - Included with Azure CLI, upgrade with `az bicep upgrade` if needed
- **Authenticated** - Run `az login` before deployment
- **Entra ID App Registration** with required API permissions (see Prerequisites section above)
- **Azure subscription** with permission to create resources

### Step 1: Deploy Infrastructure (One-Time Setup)

Deploy the Azure infrastructure (Container Registry, Log Analytics, Container App environment):

```powershell
.\infra\deploy-infrastructure.ps1 `
  -ResourceGroup "response-mcp-rg" `
  -Location "westeurope" `
  -DefenderClientId "your-app-client-id" `
  -DefenderClientSecret (ConvertTo-SecureString "your-client-secret" -AsPlainText -Force) `
  -DefenderTenantId "your-tenant-id"
```

**What happens:**
- Creates resource group, Azure Container Registry, Log Analytics workspace
- Deploys Container App with managed environment and auto-scaling
- **Auto-generates MCP API key** and configures it as a secret
- Outputs SSE endpoint URL and **displays the API key** (save it - won't be shown again!)

**Optional:** Provide your own API key:
```powershell
-McpApiKey (ConvertTo-SecureString "your-custom-api-key" -AsPlainText -Force)
```

### Step 2: Build and Deploy Container

Build the Docker image and deploy it to the Container App:

```powershell
.\infra\deploy-container.ps1 -ResourceGroup "response-mcp-rg"
```

**What happens:**
- **Builds Docker image in Azure Container Registry** (cloud build - no local Docker required)
- Uploads source code to Azure
- Builds container image on Azure infrastructure
- Creates new revision with timestamp
- Updates Container App and activates the new revision

**Note:** Docker Desktop is not required - the build happens entirely in Azure using ACR Tasks.

**For subsequent updates:** Just run Step 2 again to deploy code changes.

### Step 3: Configure VS Code

Add to your MCP settings:

```json
{
  "mcpServers": {
    "response-mcp": {
      "type": "sse",
      "url": "https://your-app.azurecontainerapps.io/sse",
      "headers": {
        "X-API-Key": "<API-KEY-FROM-STEP-1>"
      }
    }
  }
}
```

Replace the URL and API key with values from Step 1 output.

### Security Hardening: IP Allowlist (Recommended)

Restrict access to your Container App from specific IP addresses:

**Allow a single IP:**
```powershell
az containerapp ingress access-restriction set `
  --name <your-container-app-name> `
  --resource-group response-mcp-rg `
  --rule-name "AllowMyIP" `
  --action Allow `
  --ip-address "203.0.113.42/32" `
  --description "My workstation"
```

**Allow multiple IPs or ranges:**
```powershell
# Add office network
az containerapp ingress access-restriction set `
  --name <your-container-app-name> `
  --resource-group response-mcp-rg `
  --rule-name "AllowOffice" `
  --action Allow `
  --ip-address "203.0.113.0/24" `
  --description "Office network"

# Add VPN endpoint
az containerapp ingress access-restriction set `
  --name <your-container-app-name> `
  --resource-group response-mcp-rg `
  --rule-name "AllowVPN" `
  --action Allow `
  --ip-address "198.51.100.10/32" `
  --description "VPN gateway"
```

**List current rules:**
```powershell
az containerapp ingress access-restriction list `
  --name <your-container-app-name> `
  --resource-group response-mcp-rg `
  -o table
```

**Remove a rule:**
```powershell
az containerapp ingress access-restriction remove `
  --name <your-container-app-name> `
  --resource-group response-mcp-rg `
  --rule-name "AllowMyIP"
```

**Note:** IP restrictions are evaluated in order. Ensure you don't lock yourself out - test from allowed IPs before removing unrestricted access.

## Security Considerations

| Layer | Protection |
|-------|------------|
| Transport | HTTPS/TLS encryption |
| Authentication | API key in `X-API-Key` header |
| Network | IP allowlist on Container App (standard) |
| Network (Advanced) | VNet integration + Private Link/VPN (optional) |
| Secrets | Stored in Azure Container App secrets |
| Defender API | Service principal with least privilege |

**Standard Security (Current Deployment):**
- Public endpoint with IP allowlist restrictions
- API key authentication
- HTTPS/TLS encryption
- Suitable for most organizations

**Advanced Security (VNet Deployment):**

For organizations requiring private network access, deploy the Container App into a VNet:

**Benefits:**
- Private-only access (no public internet exposure)
- Access via VPN Gateway, ExpressRoute, or Azure Bastion
- Network Security Groups (NSGs) and firewall rules
- Compliance with strict network isolation policies

**Requirements:**
- Custom VNet with delegated subnet for Container Apps
- VPN Gateway (~$140/month) or ExpressRoute for remote access
- Container Apps Environment with VNet integration (`internal: true`)
- Higher base costs (~$200+/month for workload profiles)

**When to use:**
- Corporate policy requires all traffic through VPN/ExpressRoute
- No public internet endpoints allowed
- Need to access private Azure services (SQL Database with private endpoints)
- Compliance requirements mandate network isolation

**Not recommended if:**
- Accessing from individual analyst workstations (IP allowlist is simpler)
- Cost-sensitive environments
- Standard internet connectivity is acceptable

See [Azure Container Apps VNet integration](https://learn.microsoft.com/azure/container-apps/vnet-custom) for implementation details.

**Recommendations:**
- Rotate API keys regularly
- Use IP allowlisting for production environments (easiest)
- Consider VNet deployment only if required by policy/compliance
- Monitor Container App logs for suspicious activity
- Grant only required Defender API permissions
- Rotate client secrets regularly
- Never commit API keys to source control

## Cost Estimate

Estimated monthly Azure costs: **~$12-18/month** for typical usage (few analysts, business hours only). Scale-to-zero enabled to minimize idle costs. Costs increase with 24/7 operations (~$30-40/month) or higher log retention.

## Troubleshooting

**Connection refused:**
- Check Container App is running: `az containerapp show --name your-app -g your-rg`
- Verify network connectivity to Azure

**401 Unauthorized:**
- Verify your API key is correct
- Check the `X-API-Key` header is being sent
- Ensure `MCP_API_KEY` is set in Container App environment

**Defender API errors:**
- Verify app registration permissions and admin consent
- Check client secret hasn't expired
- Ensure service principal has required Defender API permissions

## License

MIT
