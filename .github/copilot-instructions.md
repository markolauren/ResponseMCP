# Security Incident Response Guidelines (example)

When responding to security incidents with endpoint alerts:

## Response Priority Order

### Endpoint Response
1. **Stop & Quarantine** - When SHA1/SHA256 hashes are available from incident evidence, immediately stop and quarantine known malicious files
2. **Restrict Code Execution** - Limit execution to Microsoft-signed applications to prevent additional attacker tools
3. **Run Antivirus Scan** - Full scan to catch any files not identified in the incident
4. **Collect Investigation Package** - Gather forensic evidence for analysis

### Identity Response
When credential compromise is detected or suspected:
1. **Force Password Reset** - Require immediate password change at next logon for compromised accounts (via `force_ad_password_reset`)
2. **Disable Account** - Temporarily disable accounts showing malicious activity or confirmed compromise (via `disable_ad_account`)
3. **Monitor for Lateral Movement** - Check for use of compromised credentials on other systems
4. **Re-enable After Remediation** - Once threat is cleared and password reset, re-enable account (via `enable_ad_account`)

## Critical Considerations
- **Business Impact**: Before isolating critical infrastructure (SQL servers, Domain Controllers, production systems), assess business impact and consider less disruptive actions first
- **Credential Compromise**: If credential theft tools (Mimikatz, etc.) are detected, assume all credentials on that device are compromised
- **Lateral Movement**: Check for signs of lateral movement and consider containment of affected user accounts

## Evidence Extraction
When analyzing incidents, always extract and present:
- File hashes (SHA1, SHA256, MD5) for malicious files
- Compromised user accounts
- Source/destination IP addresses
- MITRE ATT&CK techniques
- Affected devices and their risk scores

## Action Comments
Always include meaningful comments explaining:
- Which incident the action relates to
- What threat was detected
- Why this specific action was chosen
