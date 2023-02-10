# Windows Checklist

## High Priority
- **MAKE SURE FIREWALL AND DEFENDER ARE ON!!!!!!!!!
- Install Important patches
- 

## Medium Priority
- Disable SMBv1
- Set Windows GPO (Security)
```
Network security: LAN Manager authentication level - Send NTLMv2  response only\refuse NTLM & LM
Network security: Do not store LAN Manager hash value on next password change - Enabled
Network access: Do not allow anonymous enumeration of SAM accounts and shares - Enabled
Network access: Do not allow anonymous enumeration of SAM accounts - Enabled
Network access: Allow anonymous SID/name translation - Disabled
```
- Set Windows GPO (Audit)
```
Audit process tracking - Successes
Audit account management - Successes, Failures
Audit logon events - Successes, Failures
Audit account logon events - Successes, Failures
```
- Follow this [hardening guide](https://security.utexas.edu/os-hardening-checklist/windows-r2)

## Low Priority
- Set password policy (User Account Policies)