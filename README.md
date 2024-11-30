# Scout
Enumeration tools for Windows and Active Directory for penetration testers

## Security Note

This tool is meant for legitimate security assessment and system administration. Use responsibly and only in environments you're authorized to test.


## Scout-AD: Active Directory Permission enumeration

Scout-AD is a PowerShell script for enumerating and analyzing Active Directory permissions. It helps security professionals and administrators understand user permissions and identify potential security risks in Active Directory environments.

### Output

For each user, the script shows:
- User details (name, SamAccountName, description)
- Group memberships (sensitive groups highlighted in red)
- Effective permissions on domain objects
- Permission inheritance paths (showing which group grants specific permissions)


### Prerequisites

Either:
- Active Directory PowerShell Module (RSAT)
  ```powershell
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDA.tool~~~~0.0.1.0
  ```
OR
- PowerView.ps1 in the same directory


---

## Scout.ps1 - Windows Reconnaissance Tool
    
### Capabilities
1. File Enumeration:
    - Searches for interesting files (documents, configs, scripts)
    - Finds SSH keys and certificates
    - Locates password and credential files
    
2. Command History:
    - PowerShell console history
    - Bash history
    - WSL history files
    
3. System Enumeration:
    - Non-default scheduled tasks
    - Non-standard services and their paths
    - Running processes with full paths
    - Non-standard folders in C:\
    - Non-default applications in Program Files
    
4. User Information:
    - Currently logged in users
    - PuTTY stored credentials
    - SSH directories and keys


## License

MIT