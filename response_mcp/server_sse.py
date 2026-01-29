"""SSE-based MCP Server with API key authentication."""

import json
import logging
import os
from typing import Any

from dotenv import load_dotenv
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent

from .auth import get_access_token, GRAPH_SCOPE
from .client import DefenderClient, GraphSecurityClient

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_client() -> DefenderClient:
    """Get authenticated Defender client."""
    token = get_access_token()
    return DefenderClient(token)


def get_graph_client() -> GraphSecurityClient:
    """Get authenticated Graph Security client."""
    token = get_access_token(GRAPH_SCOPE)
    return GraphSecurityClient(token)


# Tool definitions
TOOLS = [
    Tool(
        name="echo",
        description="Test connectivity with the Response MCP server",
        inputSchema={
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Message to echo back"}
            },
            "required": ["message"],
        },
    ),
    Tool(
        name="get_machine_by_name",
        description="Find a machine/device in Microsoft Defender by hostname. Returns device details including health status, risk score, exposure level, and device ID.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_name": {"type": "string", "description": "The hostname to search for"}
            },
            "required": ["device_name"],
        },
    ),
    Tool(
        name="isolate_device",
        description="Isolate a device from the network to prevent lateral movement. Use Full isolation to block all connections, or Selective to allow Outlook/Teams/Skype.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "The unique identifier (GUID) of the device"},
                "device_name": {"type": "string", "description": "The hostname of the device (alternative to device_id)"},
                "isolation_type": {"type": "string", "enum": ["Full", "Selective"], "description": "Full blocks all connections, Selective allows Outlook/Teams/Skype"},
                "comment": {"type": "string", "description": "Comment explaining why the device is being isolated"},
            },
            "required": ["comment"],
        },
    ),
    Tool(
        name="release_device",
        description="Release a previously isolated device from network isolation, restoring full connectivity.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "The unique identifier (GUID) of the device"},
                "device_name": {"type": "string", "description": "The hostname of the device (alternative to device_id)"},
                "comment": {"type": "string", "description": "Comment explaining why the device is being released"},
            },
            "required": ["comment"],
        },
    ),
    Tool(
        name="run_antivirus_scan",
        description="Initiate a Microsoft Defender Antivirus scan on a device. Quick scan checks common malware locations, Full scan checks entire disk.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "The unique identifier (GUID) of the device"},
                "device_name": {"type": "string", "description": "The hostname of the device (alternative to device_id)"},
                "scan_type": {"type": "string", "enum": ["Quick", "Full"], "description": "Quick scans common malware locations, Full scans entire disk"},
                "comment": {"type": "string", "description": "Comment explaining why the scan is being initiated"},
            },
            "required": ["comment"],
        },
    ),
    Tool(
        name="stop_and_quarantine",
        description="Stop a running process and quarantine the associated file on a device. Requires the SHA1 hash of the file.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "The unique identifier (GUID) of the device"},
                "device_name": {"type": "string", "description": "The hostname of the device (alternative to device_id)"},
                "sha1": {"type": "string", "description": "SHA1 hash of the file to stop and quarantine"},
                "comment": {"type": "string", "description": "Comment explaining why this action is being taken"},
            },
            "required": ["sha1", "comment"],
        },
    ),
    Tool(
        name="restrict_code_execution",
        description="Restrict code execution on a device to only allow Microsoft-signed applications.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "The unique identifier (GUID) of the device"},
                "device_name": {"type": "string", "description": "The hostname of the device (alternative to device_id)"},
                "comment": {"type": "string", "description": "Comment explaining why execution is being restricted"},
            },
            "required": ["comment"],
        },
    ),
    Tool(
        name="remove_code_restriction",
        description="Remove code execution restrictions from a device, allowing all applications to run again.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "The unique identifier (GUID) of the device"},
                "device_name": {"type": "string", "description": "The hostname of the device (alternative to device_id)"},
                "comment": {"type": "string", "description": "Comment explaining why restrictions are being removed"},
            },
            "required": ["comment"],
        },
    ),
    Tool(
        name="collect_investigation_package",
        description="Collect a forensic investigation package from a device containing system information, logs, and diagnostic data. Requires MCP.Admin role.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "The unique identifier (GUID) of the device"},
                "device_name": {"type": "string", "description": "The hostname of the device (alternative to device_id)"},
                "comment": {"type": "string", "description": "Comment explaining why the package is being collected"},
            },
            "required": ["comment"],
        },
    ),
    Tool(
        name="get_investigation_package_uri",
        description="Get download URL (SAS URI) for a completed investigation package. Returns a temporary download link valid for a short time.",
        inputSchema={
            "type": "object",
            "properties": {
                "action_id": {"type": "string", "description": "The action ID from a completed collect_investigation_package action"},
            },
            "required": ["action_id"],
        },
    ),
    Tool(
        name="get_machine_actions",
        description="List recent machine actions (response actions) from Microsoft Defender. Can filter by device, action type, or status.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "Filter by device ID"},
                "device_name": {"type": "string", "description": "Filter by device name"},
                "action_type": {
                    "type": "string",
                    "enum": ["Isolate", "Unisolate", "RunAntiVirusScan", "StopAndQuarantineFile", "RestrictCodeExecution", "UnrestrictCodeExecution", "CollectInvestigationPackage"],
                    "description": "Filter by action type",
                },
                "status": {
                    "type": "string",
                    "enum": ["Pending", "InProgress", "Succeeded", "Failed", "Cancelled"],
                    "description": "Filter by status",
                },
                "limit": {"type": "integer", "description": "Maximum number of results (default 10)"},
            },
        },
    ),
    Tool(
        name="isolate_multiple",
        description="Isolate multiple devices from the network in a single operation. Provide a comma-separated list of device names.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_names": {"type": "string", "description": "Comma-separated list of device hostnames to isolate"},
                "isolation_type": {"type": "string", "enum": ["Full", "Selective"], "description": "Full blocks all connections, Selective allows Outlook/Teams/Skype"},
                "comment": {"type": "string", "description": "Comment explaining why the devices are being isolated"},
            },
            "required": ["device_names", "comment"],
        },
    ),
    Tool(
        name="get_incident",
        description="Get detailed information about a security incident by ID. Returns incident details including status, severity, classification, alerts, and timeline.",
        inputSchema={
            "type": "object",
            "properties": {
                "incident_id": {"type": "string", "description": "The incident ID (numeric string)"}
            },
            "required": ["incident_id"],
        },
    ),
    Tool(
        name="list_incidents",
        description="List security incidents with optional filtering. Can filter by status, severity, or time range.",
        inputSchema={
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["active", "resolved", "redirected"],
                    "description": "Filter by incident status"
                },
                "severity": {
                    "type": "string",
                    "enum": ["informational", "low", "medium", "high"],
                    "description": "Filter by severity level"
                },
                "top": {"type": "integer", "description": "Maximum number of results (default 50, max 100)"},
                "assigned_to": {"type": "string", "description": "Filter by assigned analyst email"},
            },
        },
    ),
    Tool(
        name="update_incident_status",
        description="Update the status of a security incident. Use this to mark incidents as active, resolved, or redirected.",
        inputSchema={
            "type": "object",
            "properties": {
                "incident_id": {"type": "string", "description": "The incident ID"},
                "status": {
                    "type": "string",
                    "enum": ["active", "resolved", "redirected"],
                    "description": "New status for the incident"
                },
                "resolving_comment": {"type": "string", "description": "Comment explaining the resolution (required when status=resolved)"},
            },
            "required": ["incident_id", "status"],
        },
    ),
    Tool(
        name="assign_incident",
        description="Assign a security incident to an analyst or remove assignment.",
        inputSchema={
            "type": "object",
            "properties": {
                "incident_id": {"type": "string", "description": "The incident ID"},
                "assigned_to": {"type": "string", "description": "Email address of analyst to assign, or null to unassign"},
            },
            "required": ["incident_id", "assigned_to"],
        },
    ),
    Tool(
        name="classify_incident",
        description="Set the classification and determination for a security incident. Use this during or after investigation to categorize the incident. To add a comment explaining the decision, use add_incident_comment separately.",
        inputSchema={
            "type": "object",
            "properties": {
                "incident_id": {"type": "string", "description": "The incident ID"},
                "classification": {
                    "type": "string",
                    "enum": ["truePositive", "falsePositive", "informationalExpectedActivity"],
                    "description": "The classification of the incident"
                },
                "determination": {
                    "type": "string",
                    "enum": ["multiStagedAttack", "malware", "securityPersonnel", "securityTesting", "unwantedSoftware", "other", "phishing", "compromisedAccount", "maliciousUserActivity", "notMalicious", "notEnoughDataToValidate", "confirmedActivity", "lineOfBusinessApplication", "apt"],
                    "description": "The determination explaining the classification. Use: notMalicious/notEnoughDataToValidate for falsePositive; multiStagedAttack/malware/phishing/compromisedAccount/maliciousUserActivity/apt/unwantedSoftware for truePositive; securityTesting/securityPersonnel/lineOfBusinessApplication/confirmedActivity for informationalExpectedActivity"
                },
            },
            "required": ["incident_id", "classification"],
        },
    ),
    Tool(
        name="add_incident_tags",
        description="Add custom tags to an incident for categorization and tracking.",
        inputSchema={
            "type": "object",
            "properties": {
                "incident_id": {"type": "string", "description": "The incident ID"},
                "tags": {"type": "string", "description": "Comma-separated list of tags to add"},
            },
            "required": ["incident_id", "tags"],
        },
    ),
    Tool(
        name="add_incident_comment",
        description="Add a comment to a security incident for documentation and collaboration.",
        inputSchema={
            "type": "object",
            "properties": {
                "incident_id": {"type": "string", "description": "The incident ID"},
                "comment": {"type": "string", "description": "The comment text to add"},
            },
            "required": ["incident_id", "comment"],
        },
    ),
    # Identity Account Actions (Active Directory via Microsoft Defender for Identity)
    Tool(
        name="disable_ad_account",
        description="Disable an Active Directory user account through Microsoft Defender for Identity. Use when credentials are compromised or account shows malicious activity. The account will be unable to authenticate.",
        inputSchema={
            "type": "object",
            "properties": {
                "user_principal_name": {"type": "string", "description": "User Principal Name (email) of the account to disable (e.g., user@domain.com)"},
                "comment": {"type": "string", "description": "Comment explaining why the account is being disabled"},
            },
            "required": ["user_principal_name", "comment"],
        },
    ),
    Tool(
        name="enable_ad_account",
        description="Re-enable a previously disabled Active Directory user account through Microsoft Defender for Identity. Use after threat has been remediated.",
        inputSchema={
            "type": "object",
            "properties": {
                "user_principal_name": {"type": "string", "description": "User Principal Name (email) of the account to enable (e.g., user@domain.com)"},
                "comment": {"type": "string", "description": "Comment explaining why the account is being re-enabled"},
            },
            "required": ["user_principal_name", "comment"],
        },
    ),
    Tool(
        name="force_ad_password_reset",
        description="Force an Active Directory user to change their password at next logon through Microsoft Defender for Identity. Use for credential theft scenarios (e.g., Mimikatz detection). Note: Does not work if 'Password never expires' is set on the account.",
        inputSchema={
            "type": "object",
            "properties": {
                "user_principal_name": {"type": "string", "description": "User Principal Name (email) of the account (e.g., user@domain.com)"},
                "comment": {"type": "string", "description": "Comment explaining why password reset is being forced"},
            },
            "required": ["user_principal_name", "comment"],
        },
    ),
    # Identity Actions (Entra ID)
    Tool(
        name="revoke_entra_sessions",
        description="Revoke all Entra ID (Azure AD) sign-in sessions and refresh tokens for a user. Forces re-authentication on all devices and applications. Use when credentials are compromised or during offboarding.",
        inputSchema={
            "type": "object",
            "properties": {
                "user_principal_name": {"type": "string", "description": "User Principal Name (email) of the account (e.g., user@domain.com)"},
                "comment": {"type": "string", "description": "Comment explaining why sessions are being revoked"},
            },
            "required": ["user_principal_name", "comment"],
        },
    ),
    Tool(
        name="confirm_user_compromised",
        description="Mark an Entra ID user as compromised in Identity Protection. Sets the user's risk level to high and triggers Conditional Access policies. Use when confirmed credential compromise is detected.",
        inputSchema={
            "type": "object",
            "properties": {
                "user_principal_name": {"type": "string", "description": "User Principal Name (email) of the account (e.g., user@domain.com)"},
                "comment": {"type": "string", "description": "Comment explaining why user is being marked as compromised"},
            },
            "required": ["user_principal_name", "comment"],
        },
    ),
    Tool(
        name="confirm_user_safe",
        description="Dismiss user risk in Identity Protection (mark as safe). Sets the user's risk level to none. Use after investigation confirms the user account is not compromised.",
        inputSchema={
            "type": "object",
            "properties": {
                "user_principal_name": {"type": "string", "description": "User Principal Name (email) of the account (e.g., user@domain.com)"},
                "comment": {"type": "string", "description": "Comment explaining why user is being marked as safe"},
            },
            "required": ["user_principal_name", "comment"],
        },
    ),
]


def handle_tool(name: str, arguments: dict[str, Any]) -> str:
    """Handle tool invocation."""
    
    if name == "echo":
        return json.dumps({
            "echo": arguments["message"],
            "status": "ok",
        })

    client = get_client()

    if name == "get_machine_by_name":
        machine = client.get_machine_by_name(arguments["device_name"])
        if not machine:
            return json.dumps({"success": False, "message": f"No machine found with name '{arguments['device_name']}'"})
        return json.dumps({
            "success": True,
            "machine": {
                "id": machine["id"],
                "name": machine["computerDnsName"],
                "os_platform": machine.get("osPlatform"),
                "health_status": machine.get("healthStatus"),
                "risk_score": machine.get("riskScore"),
                "exposure_level": machine.get("exposureLevel"),
                "last_seen": machine.get("lastSeen"),
            },
        })

    if name == "isolate_device":
        device_id = arguments.get("device_id")
        device_name = arguments.get("device_name")
        if not device_id and not device_name:
            return json.dumps({"error": {"code": "invalid_parameters", "message": "Either device_id or device_name is required"}})
        
        machine_id, machine_name = client.resolve_machine_id(device_id, device_name)
        isolation_type = arguments.get("isolation_type", "Full")
        comment = arguments["comment"]
        result = client.isolate_machine(machine_id, comment, isolation_type)
        return json.dumps({
            "success": True,
            "action": "isolate_device",
            "device_name": machine_name,
            "device_id": machine_id,
            "isolation_type": isolation_type,
            "action_id": result["id"],
            "status": result["status"],
        })

    if name == "release_device":
        device_id = arguments.get("device_id")
        device_name = arguments.get("device_name")
        if not device_id and not device_name:
            return json.dumps({"error": {"code": "invalid_parameters", "message": "Either device_id or device_name is required"}})
        
        machine_id, machine_name = client.resolve_machine_id(device_id, device_name)
        comment = arguments["comment"]
        result = client.unisolate_machine(machine_id, comment)
        return json.dumps({
            "success": True,
            "action": "release_device",
            "device_name": machine_name,
            "device_id": machine_id,
            "action_id": result["id"],
            "status": result["status"],
        })

    if name == "run_antivirus_scan":
        device_id = arguments.get("device_id")
        device_name = arguments.get("device_name")
        if not device_id and not device_name:
            return json.dumps({"error": {"code": "invalid_parameters", "message": "Either device_id or device_name is required"}})
        
        machine_id, machine_name = client.resolve_machine_id(device_id, device_name)
        scan_type = arguments.get("scan_type", "Quick")
        comment = arguments["comment"]
        result = client.run_antivirus_scan(machine_id, comment, scan_type)
        return json.dumps({
            "success": True,
            "action": "run_antivirus_scan",
            "device_name": machine_name,
            "device_id": machine_id,
            "scan_type": scan_type,
            "action_id": result["id"],
            "status": result["status"],
        })

    if name == "stop_and_quarantine":
        device_id = arguments.get("device_id")
        device_name = arguments.get("device_name")
        if not device_id and not device_name:
            return json.dumps({"error": {"code": "invalid_parameters", "message": "Either device_id or device_name is required"}})
        
        machine_id, machine_name = client.resolve_machine_id(device_id, device_name)
        comment = arguments["comment"]
        result = client.stop_and_quarantine_file(machine_id, arguments["sha1"], comment)
        return json.dumps({
            "success": True,
            "action": "stop_and_quarantine",
            "device_name": machine_name,
            "device_id": machine_id,
            "sha1": arguments["sha1"],
            "action_id": result["id"],
            "status": result["status"],
        })

    if name == "restrict_code_execution":
        device_id = arguments.get("device_id")
        device_name = arguments.get("device_name")
        if not device_id and not device_name:
            return json.dumps({"error": {"code": "invalid_parameters", "message": "Either device_id or device_name is required"}})
        
        machine_id, machine_name = client.resolve_machine_id(device_id, device_name)
        comment = arguments["comment"]
        result = client.restrict_code_execution(machine_id, comment)
        return json.dumps({
            "success": True,
            "action": "restrict_code_execution",
            "device_name": machine_name,
            "device_id": machine_id,
            "action_id": result["id"],
            "status": result["status"],
        })

    if name == "remove_code_restriction":
        device_id = arguments.get("device_id")
        device_name = arguments.get("device_name")
        if not device_id and not device_name:
            return json.dumps({"error": {"code": "invalid_parameters", "message": "Either device_id or device_name is required"}})
        
        machine_id, machine_name = client.resolve_machine_id(device_id, device_name)
        comment = arguments["comment"]
        result = client.unrestrict_code_execution(machine_id, comment)
        return json.dumps({
            "success": True,
            "action": "remove_code_restriction",
            "device_name": machine_name,
            "device_id": machine_id,
            "action_id": result["id"],
            "status": result["status"],
        })

    if name == "collect_investigation_package":
        device_id = arguments.get("device_id")
        device_name = arguments.get("device_name")
        if not device_id and not device_name:
            return json.dumps({"error": {"code": "invalid_parameters", "message": "Either device_id or device_name is required"}})
        
        machine_id, machine_name = client.resolve_machine_id(device_id, device_name)
        comment = arguments["comment"]
        result = client.collect_investigation_package(machine_id, comment)
        return json.dumps({
            "success": True,
            "action": "collect_investigation_package",
            "device_name": machine_name,
            "device_id": machine_id,
            "action_id": result["id"],
            "status": result["status"],
        })

    if name == "get_investigation_package_uri":
        action_id = arguments["action_id"]
        result = client.get_investigation_package_uri(action_id)
        return json.dumps({
            "success": True,
            "action_id": action_id,
            "download_url": result.get("value"),
        })

    if name == "get_machine_actions":
        device_id = arguments.get("device_id")
        device_name = arguments.get("device_name")
        
        # Resolve device name to ID if provided
        if device_name and not device_id:
            machine = client.get_machine_by_name(device_name)
            if machine:
                device_id = machine["id"]
        
        actions = client.get_machine_actions(
            machine_id=device_id,
            action_type=arguments.get("action_type"),
            status=arguments.get("status"),
            limit=arguments.get("limit", 10),
        )
        
        formatted = [
            {
                "id": a["id"],
                "type": a["type"],
                "status": a["status"],
                "machine_id": a["machineId"],
                "requestor": a.get("requestor"),
                "created_time": a.get("creationDateTimeUtc"),
            }
            for a in actions
        ]
        return json.dumps({
            "success": True,
            "action": "get_machine_actions",
            "count": len(formatted),
            "actions": formatted,
        })

    if name == "isolate_multiple":
        device_names_str = arguments["device_names"]
        device_names_list = [n.strip() for n in device_names_str.split(",") if n.strip()]
        
        if not device_names_list:
            return json.dumps({"error": {"code": "invalid_parameters", "message": "No device names provided"}})
        
        isolation_type = arguments.get("isolation_type", "Full")
        comment = arguments["comment"]
        results = []
        
        for dev_name in device_names_list:
            try:
                machine_id, machine_name = client.resolve_machine_id(None, dev_name)
                result = client.isolate_machine(machine_id, comment, isolation_type)
                results.append({
                    "device_name": dev_name,
                    "success": True,
                    "device_id": machine_id,
                    "action_id": result["id"],
                    "status": result["status"],
                })
            except Exception as e:
                results.append({
                    "device_name": dev_name,
                    "success": False,
                    "error": str(e),
                })
        
        succeeded = len([r for r in results if r["success"]])
        failed = len([r for r in results if not r["success"]])
        
        return json.dumps({
            "success": failed == 0,
            "action": "isolate_multiple",
            "isolation_type": isolation_type,
            "total": len(device_names_list),
            "succeeded": succeeded,
            "failed": failed,
            "results": results,
        })

    # Incident management tools (Graph Security API)
    
    graph_client = get_graph_client()
    
    if name == "get_incident":
        incident_id = arguments["incident_id"]
        incident = graph_client.get_incident(incident_id)
        return json.dumps({
            "success": True,
            "incident": {
                "id": incident.get("id"),
                "display_name": incident.get("displayName"),
                "status": incident.get("status"),
                "severity": incident.get("severity"),
                "classification": incident.get("classification"),
                "determination": incident.get("determination"),
                "assigned_to": incident.get("assignedTo"),
                "created": incident.get("createdDateTime"),
                "last_updated": incident.get("lastUpdateDateTime"),
                "alert_count": len(incident.get("alerts", [])),
                "custom_tags": incident.get("customTags", []),
                "incident_url": incident.get("incidentWebUrl"),
            }
        })
    
    if name == "list_incidents":
        filters = []
        if "status" in arguments:
            filters.append(f"status eq '{arguments['status']}'")
        if "severity" in arguments:
            filters.append(f"severity eq '{arguments['severity']}'")
        if "assigned_to" in arguments:
            filters.append(f"assignedTo eq '{arguments['assigned_to']}'")
        
        filter_query = " and ".join(filters) if filters else None
        top = arguments.get("top", 50)
        
        incidents = graph_client.list_incidents(top=min(top, 100), filter_query=filter_query)
        
        formatted = []
        for inc in incidents:
            formatted.append({
                "id": inc.get("id"),
                "display_name": inc.get("displayName"),
                "status": inc.get("status"),
                "severity": inc.get("severity"),
                "assigned_to": inc.get("assignedTo"),
                "created": inc.get("createdDateTime"),
                "classification": inc.get("classification"),
            })
        
        return json.dumps({
            "success": True,
            "count": len(formatted),
            "incidents": formatted,
        })
    
    if name == "update_incident_status":
        incident_id = arguments["incident_id"]
        updates = {"status": arguments["status"]}
        
        if "resolving_comment" in arguments:
            updates["resolvingComment"] = arguments["resolving_comment"]
        
        incident = graph_client.update_incident(incident_id, updates)
        return json.dumps({
            "success": True,
            "incident_id": incident_id,
            "new_status": incident.get("status"),
            "message": f"Incident {incident_id} status updated to {arguments['status']}",
        })
    
    if name == "assign_incident":
        incident_id = arguments["incident_id"]
        assigned_to = arguments.get("assigned_to")
        
        incident = graph_client.update_incident(incident_id, {"assignedTo": assigned_to})
        return json.dumps({
            "success": True,
            "incident_id": incident_id,
            "assigned_to": incident.get("assignedTo"),
            "message": f"Incident {incident_id} assigned to {assigned_to}",
        })
    
    if name == "classify_incident":
        incident_id = arguments["incident_id"]
        
        # API expects camelCase values for both classification and determination
        updates = {"classification": arguments["classification"]}
        
        if "determination" in arguments:
            updates["determination"] = arguments["determination"]
        
        logging.info(f"Classifying incident {incident_id} with updates: {updates}")
        
        incident = graph_client.update_incident(incident_id, updates)
        
        return json.dumps({
            "success": True,
            "incident_id": incident_id,
            "classification": incident.get("classification"),
            "determination": incident.get("determination"),
            "message": f"Incident {incident_id} classified as {arguments['classification']}",
        })
    
    if name == "add_incident_tags":
        incident_id = arguments["incident_id"]
        tags_str = arguments["tags"]
        new_tags = [t.strip() for t in tags_str.split(",") if t.strip()]
        
        # Get current incident to preserve existing tags
        incident = graph_client.get_incident(incident_id)
        current_tags = incident.get("customTags", [])
        updated_tags = list(set(current_tags + new_tags))  # Deduplicate
        
        incident = graph_client.update_incident(incident_id, {"customTags": updated_tags})
        return json.dumps({
            "success": True,
            "incident_id": incident_id,
            "tags": incident.get("customTags", []),
            "message": f"Added {len(new_tags)} tag(s) to incident {incident_id}",
        })
    
    if name == "add_incident_comment":
        incident_id = arguments["incident_id"]
        comment = arguments["comment"]
        
        result = graph_client.add_incident_comment(incident_id, comment)
        comments = result.get("value", [])
        
        return json.dumps({
            "success": True,
            "incident_id": incident_id,
            "comment_count": len(comments),
            "message": f"Comment added to incident {incident_id}",
        })

    # Identity Account Actions (Active Directory via MDI)
    if name == "disable_ad_account":
        upn = arguments["user_principal_name"]
        comment = arguments["comment"]
        
        try:
            # Step 1: Get identity account ID from MDI
            identity_account_id = graph_client.get_identity_account_id_by_upn(upn)
            
            # Step 2: Invoke disable action
            result = graph_client.invoke_identity_action(
                identity_account_id=identity_account_id,
                account_id=identity_account_id,  # For AD accounts, same as identityAccountId
                action="disable",
                identity_provider="activeDirectory"
            )
            
            return json.dumps({
                "success": True,
                "action": "disable_ad_account",
                "user_principal_name": upn,
                "identity_account_id": identity_account_id,
                "correlation_id": result.get("correlationId", ""),
                "message": f"Account {upn} has been disabled in Active Directory",
                "comment": comment,
            })
        except Exception as e:
            logger.exception(f"Failed to disable AD account {upn}")
            return json.dumps({
                "success": False,
                "error": str(e),
                "user_principal_name": upn,
            })
    
    if name == "enable_ad_account":
        upn = arguments["user_principal_name"]
        comment = arguments["comment"]
        
        try:
            # Step 1: Get identity account ID from MDI
            identity_account_id = graph_client.get_identity_account_id_by_upn(upn)
            
            # Step 2: Invoke enable action
            result = graph_client.invoke_identity_action(
                identity_account_id=identity_account_id,
                account_id=identity_account_id,
                action="enable",
                identity_provider="activeDirectory"
            )
            
            return json.dumps({
                "success": True,
                "action": "enable_ad_account",
                "user_principal_name": upn,
                "identity_account_id": identity_account_id,
                "correlation_id": result.get("correlationId", ""),
                "message": f"Account {upn} has been re-enabled in Active Directory",
                "comment": comment,
            })
        except Exception as e:
            logger.exception(f"Failed to enable AD account {upn}")
            return json.dumps({
                "success": False,
                "error": str(e),
                "user_principal_name": upn,
            })
    
    if name == "force_ad_password_reset":
        upn = arguments["user_principal_name"]
        comment = arguments["comment"]
        
        try:
            # Step 1: Get identity account ID from MDI
            identity_account_id = graph_client.get_identity_account_id_by_upn(upn)
            
            # Step 2: Invoke forcePasswordReset action
            result = graph_client.invoke_identity_action(
                identity_account_id=identity_account_id,
                account_id=identity_account_id,
                action="forcePasswordReset",
                identity_provider="activeDirectory"
            )
            
            return json.dumps({
                "success": True,
                "action": "force_ad_password_reset",
                "user_principal_name": upn,
                "identity_account_id": identity_account_id,
                "correlation_id": result.get("correlationId", ""),
                "message": f"User {upn} will be required to change password at next logon",
                "note": "This does not work if 'Password never expires' is set on the account",
                "comment": comment,
            })
        except Exception as e:
            logger.exception(f"Failed to force password reset for {upn}")
            return json.dumps({
                "success": False,
                "error": str(e),
                "user_principal_name": upn,
            })
    
    if name == "revoke_entra_sessions":
        upn = arguments["user_principal_name"]
        comment = arguments["comment"]
        
        try:
            # Revoke all sign-in sessions via Graph API
            success = graph_client.revoke_user_sign_in_sessions(upn)
            
            if success:
                return json.dumps({
                    "success": True,
                    "action": "revoke_entra_sessions",
                    "user_principal_name": upn,
                    "message": f"All Entra ID sessions and refresh tokens revoked for {upn}. User will need to re-authenticate.",
                    "comment": comment,
                })
            else:
                return json.dumps({
                    "success": False,
                    "error": "API returned failure",
                    "user_principal_name": upn,
                })
        except Exception as e:
            logger.exception(f"Failed to revoke Entra sessions for {upn}")
            return json.dumps({
                "success": False,
                "error": str(e),
                "user_principal_name": upn,
            })
    
    if name == "confirm_user_compromised":
        upn = arguments["user_principal_name"]
        comment = arguments["comment"]
        
        try:
            # Mark user as compromised in Identity Protection
            success = graph_client.confirm_user_compromised(upn)
            
            if success:
                return json.dumps({
                    "success": True,
                    "action": "confirm_user_compromised",
                    "user_principal_name": upn,
                    "message": f"User {upn} marked as compromised in Identity Protection. Risk level set to high.",
                    "note": "This will trigger Conditional Access policies and security alerts",
                    "comment": comment,
                })
            else:
                return json.dumps({
                    "success": False,
                    "error": "API returned failure",
                    "user_principal_name": upn,
                })
        except Exception as e:
            logger.exception(f"Failed to mark {upn} as compromised")
            return json.dumps({
                "success": False,
                "error": str(e),
                "user_principal_name": upn,
            })
    
    if name == "confirm_user_safe":
        upn = arguments["user_principal_name"]
        comment = arguments["comment"]
        
        try:
            # Mark user as safe in Identity Protection (dismiss risk)
            success = graph_client.confirm_user_safe(upn)
            
            if success:
                return json.dumps({
                    "success": True,
                    "action": "confirm_user_safe",
                    "user_principal_name": upn,
                    "message": f"User {upn} marked as safe in Identity Protection. Risk level set to none.",
                    "note": "Risk has been dismissed - use after confirming no actual compromise occurred",
                    "comment": comment,
                })
            else:
                return json.dumps({
                    "success": False,
                    "error": "API returned failure",
                    "user_principal_name": upn,
                })
        except Exception as e:
            logger.exception(f"Failed to mark {upn} as safe")
            return json.dumps({
                "success": False,
                "error": str(e),
                "user_principal_name": upn,
            })

    # Entra ID Actions - Placeholders (not yet supported by API)
    # Uncomment when Microsoft adds Entra ID support to the identity actions API
    
    # if name == "revoke_entra_sessions":
    #     upn = arguments["user_principal_name"]
    #     comment = arguments["comment"]
    #     
    #     try:
    #         identity_account_id = graph_client.get_identity_account_id_by_upn(upn)
    #         result = graph_client.invoke_identity_action(
    #             identity_account_id=identity_account_id,
    #             account_id=identity_account_id,
    #             action="revokeAllSessions",
    #             identity_provider="entraID"
    #         )
    #         return json.dumps({
    #             "success": True,
    #             "action": "revoke_entra_sessions",
    #             "user_principal_name": upn,
    #             "message": f"All active sessions revoked for {upn}",
    #         })
    #     except Exception as e:
    #         return json.dumps({"success": False, "error": str(e)})
    
    # if name == "require_entra_signin":
    #     upn = arguments["user_principal_name"]
    #     comment = arguments["comment"]
    #     
    #     try:
    #         identity_account_id = graph_client.get_identity_account_id_by_upn(upn)
    #         result = graph_client.invoke_identity_action(
    #             identity_account_id=identity_account_id,
    #             account_id=identity_account_id,
    #             action="requireUserToSignInAgain",
    #             identity_provider="entraID"
    #         )
    #         return json.dumps({
    #             "success": True,
    #             "action": "require_entra_signin",
    #             "user_principal_name": upn,
    #             "message": f"User {upn} will be required to sign in again",
    #         })
    #     except Exception as e:
    #         return json.dumps({"success": False, "error": str(e)})
    
    # if name == "mark_entra_user_compromised":
    #     upn = arguments["user_principal_name"]
    #     comment = arguments["comment"]
    #     
    #     try:
    #         identity_account_id = graph_client.get_identity_account_id_by_upn(upn)
    #         result = graph_client.invoke_identity_action(
    #             identity_account_id=identity_account_id,
    #             account_id=identity_account_id,
    #             action="markUserAsCompromised",
    #             identity_provider="entraID"
    #         )
    #         return json.dumps({
    #             "success": True,
    #             "action": "mark_entra_user_compromised",
    #             "user_principal_name": upn,
    #             "message": f"User {upn} marked as compromised in Identity Protection",
    #         })
    #     except Exception as e:
    #         return json.dumps({"success": False, "error": str(e)})

    return json.dumps({"error": {"code": "unknown_tool", "message": f"Unknown tool: {name}"}})


# Create MCP server
mcp_server = Server("response-mcp")


@mcp_server.list_tools()
async def list_tools():
    return TOOLS


@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]):
    try:
        result = handle_tool(name, arguments)
        return [TextContent(type="text", text=result)]
    except Exception as e:
        logger.exception(f"Error executing tool {name}")
        error_result = json.dumps({"error": {"code": "exception", "message": str(e)}})
        return [TextContent(type="text", text=error_result)]


# SSE transport
sse_transport = SseServerTransport("/sse")


async def health_check(request: Request):
    """Health check endpoint."""
    return JSONResponse({"status": "healthy", "server": "response-mcp"})


# Create Starlette app
async def sse_endpoint(scope, receive, send):
    """ASGI endpoint for SSE - bypasses Starlette routing."""
    request = Request(scope, receive, send)
    
    # Check authentication
    skip_auth = os.environ.get("MCP_SKIP_AUTH", "").lower() == "true"
    
    if not skip_auth:
        api_key = os.environ.get("MCP_API_KEY", "")
        request_api_key = request.headers.get("X-API-Key", "")
        
        if not api_key or request_api_key != api_key:
            response = JSONResponse({"error": "Invalid API key"}, status_code=401)
            await response(scope, receive, send)
            return
    
    # Route to SSE transport handlers
    if request.method == "GET":
        async with sse_transport.connect_sse(scope, receive, send) as streams:
            await mcp_server.run(streams[0], streams[1], mcp_server.create_initialization_options())
    elif request.method == "POST":
        await sse_transport.handle_post_message(scope, receive, send)
    else:
        response = JSONResponse({"error": "Method not allowed"}, status_code=405)
        await response(scope, receive, send)


# Custom ASGI app that routes to health or SSE
async def root_app(scope, receive, send):
    """Root ASGI app with custom routing."""
    path = scope.get("path", "")
    
    if path == "/health":
        request = Request(scope, receive, send)
        response = await health_check(request)
        await response(scope, receive, send)
    elif path == "/sse":
        await sse_endpoint(scope, receive, send)
    else:
        response = JSONResponse({"error": "Not found"}, status_code=404)
        await response(scope, receive, send)


# Wrap with CORS middleware
from starlette.middleware.cors import CORSMiddleware as CORSMiddlewareClass

app = CORSMiddlewareClass(
    app=root_app,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def main():
    """Run the SSE server."""
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    
    logger.info(f"Starting Response MCP Server on {host}:{port}")
    logger.info(f"SSE endpoint: http://{host}:{port}/sse")
    logger.info(f"Health check: http://{host}:{port}/health")
    
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
