"""Client credentials authentication for Defender API and Graph API."""

import os
import time
from typing import Optional

import msal
from dotenv import load_dotenv

load_dotenv()

DEFENDER_SCOPE = "https://api.securitycenter.microsoft.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

_token_cache: dict[str, dict] = {
    "defender": {"access_token": None, "expires_at": 0},
    "graph": {"access_token": None, "expires_at": 0},
}


def get_config() -> dict:
    """Get credentials from environment."""
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    if not all([tenant_id, client_id, client_secret]):
        raise ValueError(
            "Missing credentials. Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET in .env"
        )

    return {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "client_secret": client_secret,
    }


def get_access_token(scope: str = DEFENDER_SCOPE) -> str:
    """Get access token using client credentials flow.
    
    Args:
        scope: Either DEFENDER_SCOPE or GRAPH_SCOPE. Defaults to DEFENDER_SCOPE.
    """
    global _token_cache

    # Determine cache key
    cache_key = "graph" if scope == GRAPH_SCOPE else "defender"
    
    # Check if cached token is still valid (with 5 min buffer)
    cache = _token_cache[cache_key]
    if cache["access_token"] and cache["expires_at"] > time.time() + 300:
        return cache["access_token"]

    config = get_config()

    app = msal.ConfidentialClientApplication(
        config["client_id"],
        authority=f"https://login.microsoftonline.com/{config['tenant_id']}",
        client_credential=config["client_secret"],
    )

    result = app.acquire_token_for_client(scopes=[scope])

    if "access_token" not in result:
        error = result.get("error_description", result.get("error", "Unknown error"))
        raise ValueError(f"Failed to acquire token for {scope}: {error}")

    _token_cache[cache_key] = {
        "access_token": result["access_token"],
        "expires_at": time.time() + result.get("expires_in", 3600),
    }

    return _token_cache[cache_key]["access_token"]
