# Scout-AD.ps1
# Active Directory enumeration script for security auditing
# Supports both ActiveDirectory module and PowerView

$global:enumMethod = $null
$global:powerViewPath = ".\PowerView.ps1"

function Convert-NameToSid {
    param([string]$ObjectName)
    if ($global:enumMethod -eq "ADModule") {
        try {
            $obj = Get-ADObject -Filter {SamAccountName -eq $ObjectName}
            return $obj.ObjectSID
        } catch {
            Write-Error "Error converting name to SID: $_"
            return $null
        }
    } else {
        try {
            return ConvertTo-SID $ObjectName
        } catch {
            Write-Error "Error converting name to SID: $_"
            return $null
        }
    }
}

function Convert-SidToName {
    param([string]$ObjectSid)
    if ($global:enumMethod -eq "ADModule") {
        try {
            $obj = Get-ADObject -Identity $ObjectSid
            return $obj.Name
        } catch {
            return $ObjectSid
        }
    } else {
        try {
            return ConvertFrom-SID $ObjectSid
        } catch {
            return $ObjectSid
        }
    }
}

function Test-ImportantGroup {
    param (
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    
    return $GroupName -match "admin|Domain|Enterprise|Schema|Backup|DNSAdmin|Exchange|OU|GPO"
}

function Format-GroupName {
    param (
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    
    return "  - $GroupName"
}

function Get-EffectiveAcls {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Principal,
        
        [Parameter(Mandatory=$true)]
        [string]$Target
    )
    
    try {
        Write-Verbose "Getting SID for principal: $Principal"
        $PrincipalSID = Convert-NameToSid $Principal
        if (-not $PrincipalSID) {
            Write-Error "Could not resolve SID for principal: $Principal"
            return
        }

        Write-Verbose "Getting group memberships for: $Principal"
        if ($global:enumMethod -eq "ADModule") {
            $GroupSIDs = Get-ADPrincipalGroupMembership $Principal | 
                Select-Object -ExpandProperty SID
        } else {
            $GroupSIDs = Get-DomainGroup -MemberIdentity $Principal | 
                Select-Object -ExpandProperty objectsid
        }
        
        $AllSIDs = @($PrincipalSID) + $GroupSIDs
        
        Write-Verbose "Found $($AllSIDs.Count) total SIDs (including groups)"
        
        Write-Verbose "Getting ACLs for target: $Target"
        if ($global:enumMethod -eq "ADModule") {
            $targetDN = (Get-ADObject -Filter {Name -eq $Target}).DistinguishedName
            $ACLs = (Get-Acl "AD:$targetDN").Access | 
                Where-Object { $AllSIDs -contains $_.IdentityReference }
        } else {
            $ACLs = Get-ObjectAcl -Identity $Target -ResolveGUIDs | 
                Where-Object { $AllSIDs -contains $_.SecurityIdentifier }
        }
        
        # Add custom type name for formatting
        $ACLs | ForEach-Object {
            $_ | Add-Member -NotePropertyName PrincipalName -NotePropertyValue $Principal -Force
            $_ | Add-Member -NotePropertyName TargetName -NotePropertyValue $Target -Force
            
            # Try to resolve the group name if the ACE is through group membership
            if ($_.SecurityIdentifier -ne $PrincipalSID) {
                $GroupName = Convert-SidToName $_.SecurityIdentifier
                $_ | Add-Member -NotePropertyName ViaGroup -NotePropertyValue $GroupName -Force
            }
        }
        
        return $ACLs
    } catch {
        Write-Error "An error occurred: $_"
        Write-Error $_.ScriptStackTrace
    }
}

# Check available methods and load required components
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Host "[+] Using Active Directory module" -ForegroundColor Green
    Import-Module ActiveDirectory
    $global:enumMethod = "ADModule"
}
elseif (Test-Path $powerViewPath) {
    Write-Host "[+] Attempting to load PowerView..." -ForegroundColor Yellow
    try {
        Import-Module $powerViewPath -Force
        Write-Host "[+] PowerView loaded successfully" -ForegroundColor Green
        $global:enumMethod = "PowerView"
    }
    catch {
        Write-Host "[-] Error loading PowerView: $_" -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "`n[-] Neither Active Directory module nor PowerView.ps1 found!" -ForegroundColor Red
    Write-Host "`nTo use this script, you need either:" -ForegroundColor Yellow
    
    Write-Host "`n1. Active Directory module:" -ForegroundColor Cyan
    Write-Host "   Option A - Using PowerShell as administrator:"
    Write-Host "   Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDA.tool~~~~0.0.1.0"
    Write-Host "   Option B - Using Windows Features:"
    Write-Host "   - Go to Settings > Apps > Optional Features"
    Write-Host "   - Add 'RSAT: Active Directory Domain Services'"
    
    Write-Host "`n2. PowerView:" -ForegroundColor Cyan
    Write-Host "   - Place PowerView.ps1 in the same directory as this script"
    Write-Host "   - Ensure PowerView.ps1 is not blocked (Right-click > Properties > Unblock)"
    
    exit 1
}

function Get-DomainUsers {
    if ($global:enumMethod -eq "ADModule") {
        return Get-ADUser -Filter * -Properties Description, Info, MemberOf
    }
    else {
        return Get-DomainUser | Where-Object { $_.samaccountname -ne $null }
    }
}

function Get-UserGroups {
    param (
        [Parameter(Mandatory=$true)]
        $User
    )
    
    if ($global:enumMethod -eq "ADModule") {
        return $User.MemberOf | ForEach-Object {
            (Get-ADGroup $_).Name
        }
    }
    else {
        return Get-DomainGroup -MemberIdentity $User.samaccountname | 
            Select-Object -ExpandProperty samaccountname
    }
}

function Get-ImportantObjects {
    if ($global:enumMethod -eq "ADModule") {
        # Get important AD objects like Domain Admins, Enterprise Admins, etc.
        return Get-ADGroup -Filter {
            Name -like "*admin*" -or 
            Name -like "*Domain*" -or 
            Name -like "*Enterprise*" -or 
            Name -eq "Schema Admins"
        }
    } else {
        return Get-DomainGroup | Where-Object {
            $_.name -like "*admin*" -or 
            $_.name -like "*Domain*" -or 
            $_.name -like "*Enterprise*" -or 
            $_.name -eq "Schema Admins"
        }
    }
}

# Main execution
Write-Host "`n=== Domain Users and Their Permissions ===" -ForegroundColor Cyan
$users = Get-DomainUsers

foreach ($user in $users) {
    Write-Host "`nUser: $($user.Name)" -ForegroundColor Green
    Write-Host "SamAccountName: $($user.SamAccountName)" -ForegroundColor Green
    
    # Display Description if exists and not empty
    if ($user.Description -and $user.Description.Trim()) {
        Write-Host "Description: $($user.Description)" -ForegroundColor Green
    }
    
    # Display Info if exists and not empty
    if ($user.Info -and $user.Info.Trim()) {
        Write-Host "Info: $($user.Info)" -ForegroundColor Green
    }
    
    # Get group memberships with highlighting
    Write-Host "`nGroup Memberships:" -ForegroundColor Yellow
    $groups = Get-UserGroups -User $user
    if ($groups) {
        $groups | ForEach-Object {
            $formattedGroup = Format-GroupName $_
            if (Test-ImportantGroup $_) {
                Write-Host $formattedGroup -ForegroundColor Red
            } else {
                Write-Host $formattedGroup
            }
        }
    } else {
        Write-Host "  No group memberships found"
    }
    
     # Get effective permissions
    Write-Host "`nEffective Permissions:" -ForegroundColor Yellow
    $allGroups = Get-DomainGroup # Get all domain groups
    foreach ($group in $allGroups) {
        $perms = Get-EffectiveAcls -Principal $user.SamAccountName -Target $group.Name
        if ($perms) {
            # Determine if this is an important group
            $isImportant = Test-ImportantGroup $group.Name
            $color = if ($isImportant) { "Red" } else { "Cyan" }
            
            Write-Host "`n  Target: $($group.Name)" -ForegroundColor $color
            foreach ($perm in $perms) {
                Write-Host "    Rights: $($perm.ActiveDirectoryRights)"
                if ($perm.ViaGroup) {
                    Write-Host "    Via Group: $($perm.ViaGroup)"
                }
                Write-Host "    Access Type: $($perm.AccessControlType)"
                Write-Host "    Inheritance Type: $($perm.InheritanceType)"
                Write-Host "    Object Type: $($perm.ObjectType)`n"
            }
        }
    }
    
    Write-Host ("-" * 80)
}