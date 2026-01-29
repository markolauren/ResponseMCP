"""Microsoft Defender for Endpoint API client and Graph Security API client."""

from typing import Optional
import httpx
import logging

DEFENDER_API_BASE = "https://api.securitycenter.microsoft.com"
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"


class DefenderClient:
    """Client for Defender API."""

    def __init__(self, access_token: str):
        self.access_token = access_token
        self.client = httpx.Client(
            base_url=DEFENDER_API_BASE,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

    def _request(self, method: str, path: str, json: Optional[dict] = None) -> dict:
        response = self.client.request(method, path, json=json)
        response.raise_for_status()
        if response.status_code == 204:
            return {}
        return response.json()

    # Machine lookup

    def get_machine_by_name(self, device_name: str) -> Optional[dict]:
        result = self._request("GET", f"/api/machines?$filter=computerDnsName eq '{device_name}'")
        machines = result.get("value", [])
        return machines[0] if machines else None

    def get_machine_by_id(self, machine_id: str) -> dict:
        return self._request("GET", f"/api/machines/{machine_id}")

    def resolve_machine_id(self, device_id: Optional[str], device_name: Optional[str]) -> tuple[str, str]:
        """Resolve to (id, name) tuple."""
        if device_id:
            machine = self.get_machine_by_id(device_id)
            return machine["id"], machine["computerDnsName"]
        if device_name:
            machine = self.get_machine_by_name(device_name)
            if not machine:
                raise ValueError(f"No device found with name '{device_name}'")
            return machine["id"], machine["computerDnsName"]
        raise ValueError("Either device_id or device_name is required")

    # Response actions

    def isolate_machine(self, machine_id: str, comment: str, isolation_type: str = "Full") -> dict:
        return self._request("POST", f"/api/machines/{machine_id}/isolate", {
            "Comment": comment,
            "IsolationType": isolation_type,
        })

    def unisolate_machine(self, machine_id: str, comment: str) -> dict:
        return self._request("POST", f"/api/machines/{machine_id}/unisolate", {
            "Comment": comment,
        })

    def run_antivirus_scan(self, machine_id: str, comment: str, scan_type: str = "Quick") -> dict:
        return self._request("POST", f"/api/machines/{machine_id}/runAntiVirusScan", {
            "Comment": comment,
            "ScanType": scan_type,
        })

    def stop_and_quarantine_file(self, machine_id: str, sha1: str, comment: str) -> dict:
        return self._request("POST", f"/api/machines/{machine_id}/StopAndQuarantineFile", {
            "Comment": comment,
            "Sha1": sha1,
        })

    def restrict_code_execution(self, machine_id: str, comment: str) -> dict:
        return self._request("POST", f"/api/machines/{machine_id}/restrictCodeExecution", {
            "Comment": comment,
        })

    def unrestrict_code_execution(self, machine_id: str, comment: str) -> dict:
        return self._request("POST", f"/api/machines/{machine_id}/unrestrictCodeExecution", {
            "Comment": comment,
        })

    def collect_investigation_package(self, machine_id: str, comment: str) -> dict:
        return self._request("POST", f"/api/machines/{machine_id}/collectInvestigationPackage", {
            "Comment": comment,
        })

    def get_investigation_package_uri(self, action_id: str) -> dict:
        return self._request("GET", f"/api/machineactions/{action_id}/GetPackageUri")

    def get_machine_actions(
        self,
        machine_id: Optional[str] = None,
        action_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 10,
    ) -> list:
        filters = []
        if machine_id:
            filters.append(f"machineId eq '{machine_id}'")
        if action_type:
            filters.append(f"type eq '{action_type}'")
        if status:
            filters.append(f"status eq '{status}'")

        url = f"/api/machineactions?$top={limit}"
        if filters:
            url += f"&$filter={' and '.join(filters)}"

        result = self._request("GET", url)
        return result.get("value", [])


class GraphSecurityClient:
    """Client for Microsoft Graph Security API."""

    def __init__(self, access_token: str):
        self.access_token = access_token
        self.client = httpx.Client(
            base_url=GRAPH_API_BASE,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

    def _request(self, method: str, path: str, json: Optional[dict] = None) -> dict:
        response = self.client.request(method, path, json=json)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            # Log the error response body for debugging
            error_body = response.text
            logging.error(f"HTTP {response.status_code} for {method} {path}: {error_body}")
            logging.error(f"Request body was: {json}")
            raise
        if response.status_code == 204:
            return {}
        return response.json()

    # Incident operations

    def get_incident(self, incident_id: str) -> dict:
        """Get incident by ID."""
        return self._request("GET", f"/security/incidents/{incident_id}")

    def list_incidents(
        self,
        top: int = 50,
        skip: int = 0,
        filter_query: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> list:
        """List security incidents with optional filtering and pagination."""
        params = []
        params.append(f"$top={top}")
        if skip > 0:
            params.append(f"$skip={skip}")
        if filter_query:
            params.append(f"$filter={filter_query}")
        if order_by:
            params.append(f"$orderby={order_by}")

        url = f"/security/incidents?{'&'.join(params)}"
        result = self._request("GET", url)
        return result.get("value", [])

    def update_incident(self, incident_id: str, updates: dict) -> dict:
        """Update incident properties.
        
        Updatable fields: status, assignedTo, classification, determination, 
        customTags, description, severity, resolvingComment, summary
        """
        return self._request("PATCH", f"/security/incidents/{incident_id}", updates)

    def add_incident_comment(self, incident_id: str, comment: str) -> dict:
        """Add a comment to an incident using the proper API endpoint."""
        return self._request("POST", f"/security/incidents/{incident_id}/comments", {
            "@odata.type": "microsoft.graph.security.alertComment",
            "comment": comment
        })

    # Identity Account Actions (Microsoft Defender for Identity)
    
    def get_identity_account_id_by_upn(self, upn: str) -> str:
        """
        Resolve User Principal Name to Microsoft Defender for Identity account ID.
        
        This queries the MDI identityAccounts API to find the tracking entity ID
        for the given user. This ID is required for invoking identity actions.
        
        Requires: SecurityIdentitiesAccount.Read.All permission
        """
        # Query all identity accounts (using full URL to access beta endpoint)
        response = self.client.request("GET", "https://graph.microsoft.com/beta/security/identities/identityAccounts")
        response.raise_for_status()
        result = response.json()
        accounts = result.get("value", [])
        
        # Search for matching account by UPN
        for account in accounts:
            account_upn = account.get("userPrincipalName", "")
            if account_upn and account_upn.lower() == upn.lower():
                return account["id"]
        
        raise ValueError(f"No identity account found in MDI for UPN: {upn}. User may not be tracked by Microsoft Defender for Identity.")
    
    def invoke_identity_action(
        self,
        identity_account_id: str,
        account_id: str,
        action: str,
        identity_provider: str
    ) -> dict:
        """
        Invoke a response action on an identity account through Microsoft Defender for Identity.
        
        Args:
            identity_account_id: The MDI identity account tracking ID
            account_id: The actual account identifier (AD GUID or Azure AD Object ID)
            action: The action to perform (disable, enable, forcePasswordReset, etc.)
            identity_provider: activeDirectory, entraID, or okta
        
        Supported actions by provider:
        - activeDirectory: disable, enable, forcePasswordReset
        - entraID: NOT YET SUPPORTED (API returns "EntraID actions are not yet supported")
        - okta: disable, enable, revokeAllSessions
        
        Requires: SecurityIdentitiesActions.ReadWrite.All permission
        """
        url = f"https://graph.microsoft.com/beta/security/identities/identityAccounts/{identity_account_id}/invokeAction"
        body = {
            "accountId": account_id,
            "action": action,
            "identityProvider": identity_provider
        }
        
        response = self.client.request("POST", url, json=body)
        response.raise_for_status()
        return response.json()
    
    def revoke_user_sign_in_sessions(self, user_principal_name: str) -> bool:
        """
        Revoke all refresh tokens and sessions for a user (Entra ID).
        
        Forces the user to re-authenticate on all devices and applications.
        This invalidates all refresh tokens issued to applications for the user.
        
        Args:
            user_principal_name: The UPN of the user (e.g., user@domain.com)
        
        Returns:
            bool: True if sessions were successfully revoked
        
        Requires: User.RevokeSessions.All permission
        """
        url = f"/users/{user_principal_name}/revokeSignInSessions"
        response = self._request("POST", url)
        # API returns {"value": true} on success
        return response.get("value", False)
    
    def get_user_id_by_upn(self, user_principal_name: str) -> str:
        """
        Get the Entra ID user object ID from UPN.
        
        Args:
            user_principal_name: The UPN of the user (e.g., user@domain.com)
        
        Returns:
            str: The Entra ID object ID
        
        Requires: User.Read.All permission
        """
        url = f"/users/{user_principal_name}"
        user = self._request("GET", url)
        return user["id"]
    
    def confirm_user_compromised(self, user_principal_name: str) -> bool:
        """
        Mark an Entra ID user as compromised in Identity Protection.
        
        Sets the user's risk level to high in Entra ID Identity Protection.
        This triggers Conditional Access policies and alerts security teams.
        
        Args:
            user_principal_name: The UPN of the user (e.g., user@domain.com)
        
        Returns:
            bool: True if user was successfully marked as compromised
        
        Requires: IdentityRiskyUser.ReadWrite.All permission
        """
        # First get the user's object ID
        user_id = self.get_user_id_by_upn(user_principal_name)
        
        # Confirm user as compromised
        url = "/identityProtection/riskyUsers/confirmCompromised"
        self._request("POST", url, {"userIds": [user_id]})
        
        # API returns 204 No Content on success
        return True
    
    def confirm_user_safe(self, user_principal_name: str) -> bool:
        """
        Mark an Entra ID user as safe in Identity Protection (dismiss risk).
        
        Sets the user's risk level to none in Entra ID Identity Protection.
        Use this after investigation confirms no actual compromise occurred.
        
        Args:
            user_principal_name: The UPN of the user (e.g., user@domain.com)
        
        Returns:
            bool: True if user was successfully marked as safe
        
        Requires: IdentityRiskyUser.ReadWrite.All permission
        """
        # First get the user's object ID
        user_id = self.get_user_id_by_upn(user_principal_name)
        
        # Confirm user as safe
        url = "/identityProtection/riskyUsers/confirmSafe"
        self._request("POST", url, {"userIds": [user_id]})
        
        # API returns 204 No Content on success
        return True

