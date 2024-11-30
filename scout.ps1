<#
    Scout.ps1 - Windows Reconnaissance Tool
    For OSCP exam preparation
    
    Capabilities:
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
#>

function Show-Banner {
    Write-Host @"
    ____                  __  
   / __/______ __  ___  / /_ 
  _\ \/ __/ _ `/ |/ / _  __/
 /___/\__/\_,_/|___/  \__/  
                                
 Windows File Reconnaissance Tool
"@ -ForegroundColor Cyan
    Write-Host "`n[*] Starting reconnaissance...`n" -ForegroundColor Blue
}

function Get-NonDefaultFolders {
    Write-Host "`n[*] Checking for non-default folders in C:\" -ForegroundColor Blue
    
    $defaultFolders = @(
        'PerfLogs',
        'Program Files',
        'Program Files (x86)',
        'Users',
        'Windows',
        'output.txt'
    )
    
    Get-ChildItem -Path "C:\" -Directory | Where-Object {
        $_.Name -notin $defaultFolders
    } | ForEach-Object {
        Write-Host "[+] Found non-default folder: $($_.FullName)" -ForegroundColor Yellow
    }
}

function Get-NonDefaultPrograms {
    Write-Host "`n[*] Checking for non-default programs" -ForegroundColor Blue
    
    $defaultPrograms = @(
        'Common Files', 
        'Internet Explorer',
        'Microsoft Update Health Tools',
        'ModifiableWindowsApps',
        'VMware',
        'Windows Defender',
        'Windows Defender Advanced Threat Protection',
        'Windows Mail',
        'Windows Media Player',
        'Windows NT',
        'Windows Photo Viewer',
        'WindowsPowerShell'
    )
    
    # Check Program Files
    Get-ChildItem -Path "C:\Program Files" -Directory | Where-Object {
        $_.Name -notin $defaultPrograms
    } | ForEach-Object {
        Write-Host "[+] Found non-default program (x64): $($_.Name)" -ForegroundColor Yellow
    }
    
    # Check Program Files (x86)
    if (Test-Path "C:\Program Files (x86)") {
        Get-ChildItem -Path "C:\Program Files (x86)" -Directory | Where-Object {
            $_.Name -notin $defaultPrograms
        } | ForEach-Object {
            Write-Host "[+] Found non-default program (x86): $($_.Name)" -ForegroundColor Yellow
        }
    }
}

function Get-NonDefaultScheduledTasks {
    Write-Host "`n[*] Checking for non-default scheduled tasks" -ForegroundColor Blue
    
    Get-ScheduledTask | Where-Object {
        $_.TaskPath -notlike "\Microsoft\*" -and
        $_.TaskPath -notlike "\Windows\*"
    } | ForEach-Object {
        $task = $_
        $taskDetail = $task | Get-ScheduledTaskInfo
        Write-Host "[+] Task: $($task.TaskName)" -ForegroundColor Yellow
        Write-Host "    Path: $($task.TaskPath)"
        Write-Host "    State: $($task.State)"
        Write-Host "    Author: $($task.Author)"
        Write-Host "    Run As: $($task.Principal.UserId)"
        Write-Host "    Command: $($task.Actions.Execute) $($task.Actions.Arguments)"
        Write-Host "    Last Run: $($taskDetail.LastRunTime)"
        Write-Host "    Next Run: $($taskDetail.NextRunTime)`n"
    }
}

function Get-NonDefaultServices {
    Write-Host "`n[*] Checking for non-default services" -ForegroundColor Blue
    
    Get-WmiObject Win32_Service | Where-Object {
        $_.PathName -notlike "*system32*" -and
        $_.PathName -notlike "*System32*" -and
        $_.PathName -notlike "*WINDOWS*" -and
        $_.PathName -notlike "*Program Files*\Windows*" -and
        $_.PathName -notlike "*Program Files (x86)\Microsoft*" -and  # Added this line
        $_.PathName -notlike "*Program Files\VMware*"                # Added this line
    } | ForEach-Object {
        Write-Host "[+] Service: $($_.DisplayName)" -ForegroundColor Yellow
        Write-Host "    Name: $($_.Name)"
        Write-Host "    State: $($_.State)"
        Write-Host "    Start Mode: $($_.StartMode)"
        Write-Host "    Run As: $($_.StartName)"
        Write-Host "    Path: $($_.PathName)`n"
    }
}

function Get-RunningProcesses {
    Write-Host "`n[*] Getting running processes with full paths" -ForegroundColor Blue
    
    Get-Process | Where-Object {
        $_.Path -notlike "*system32*" -and
        $_.Path -notlike "*System32*" -and
        $_.Path -notlike "*WINDOWS*" -and
        $_.Path -notlike "*Program Files*\Windows*" -and
        $_.ProcessName -ne "msedgewebview2"  # Added this line
    } | ForEach-Object {
        if ($_.Path) {
            Write-Host "[+] Process: $($_.ProcessName)" -ForegroundColor Yellow
            Write-Host "    PID: $($_.Id)"
            Write-Host "    Path: $($_.Path)`n"
        }
    }
}

function Get-LoggedInUsers {
    Write-Host "`n[*] Getting logged in users" -ForegroundColor Blue
    
    Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName | ForEach-Object {
        Write-Host "[+] Logged in user: $($_.UserName)" -ForegroundColor Yellow
    }
    
    quser 2>$null | ForEach-Object {
        Write-Host "[+] User session: $_" -ForegroundColor Yellow
    }
}

function Get-PuttyCredentials {
    Write-Host "`n[*] Checking for PuTTY stored credentials" -ForegroundColor Blue
    
    $puttyRegPath = "Registry::HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions"
    if (Test-Path $puttyRegPath) {
        Get-ChildItem $puttyRegPath | ForEach-Object {
            $session = Get-ItemProperty $_.PSPath
            if ($session.HostName) {
                Write-Host "[+] PuTTY Session: $($_.PSChildName)" -ForegroundColor Yellow
                Write-Host "    Hostname: $($session.HostName)"
                Write-Host "    Username: $($session.UserName)"
                Write-Host "    Port: $($session.PortNumber)`n"
            }
        }
    }
}

function Get-HistoryFiles {
    Write-Host "[*] Checking for command history files..." -ForegroundColor Blue
    
    # Common history file locations
    $historyPaths = @{
        "PowerShell" = @(
            "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
            "$HOME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        )
        "Bash" = @(
            "C:\Users\*\.bash_history",
            "C:\Program Files\Git\*\.bash_history"
        )
        "Command Prompt" = @(
            "C:\Users\*\AppData\Local\Microsoft\Windows\History\*",
            "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*"
        )
        "WSL" = @(
            "C:\Users\*\AppData\Local\Packages\*\LocalState\rootfs\home\*\.bash_history",
            "C:\Users\*\AppData\Local\Packages\*\LocalState\rootfs\home\*\.zsh_history"
        )
    }

    $historyResults = @()

    foreach ($shellName in $historyPaths.Keys) {
        foreach ($path in $historyPaths[$shellName]) {
            try {
                $files = Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    Write-Host "[+] Found $shellName history: $($file.FullName)" -ForegroundColor Yellow
                    
                    try {
                        $content = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue
                        if ($content) {
                            $historyResults += [PSCustomObject]@{
                                Shell = $shellName
                                Path = $file.FullName
                                Content = $content
                                LastModified = $file.LastWriteTime
                            }
                        }
                    } catch {
                        Write-Host "[!] Couldn't read history file: $($file.FullName)" -ForegroundColor Red
                    }
                }
            } catch {
                continue
            }
        }
    }
    
    return $historyResults
}

$excludedPaths = @(
    'C:\Windows',
    'C:\Program Files',
    'C:\Program Files (x86)',
    'C:\ProgramData\Microsoft',
    'C:\Users\*\AppData'
)

# Extended list of interesting extensions including SSH and crypto files
$interestingExtensions = @(
    # Documents and configs
    '*.txt', '*.doc*', '*.xls*', '*.pdf', '*.conf', '*.config',
    '*.ini', '*.sql', '*.db', '*.kdbx', '*.log', '*.bak',
    '*.backup', '*.xml', '*.json', '*.yml', '*.yaml', '*.csv',
    
    # Scripts and source code
    '*.ps1', '*.psm1', '*.psd1', '*.bat', '*.cmd', '*.vbs',
    
    # Keys and certificates
    '*.key', '*.pem', '*.cer', '*.crt', '*.csr', '*.der', '*.p7b',
    '*.p12', '*.pfx', '*.jks', '*.keystore', '*.pub',
    
    # SSH specific
    'id_rsa*', 'id_dsa*', 'id_ecdsa*', 'id_ed25519*',
    'known_hosts', 'authorized_keys', 'config',
    
    # PuTTY specific
    '*.ppk', '*.asc',
    
    # Password and secret files
    '*.pwd', '*.pass', '*.secret', '*.credentials',

    # History files
    '*.history', '*_history', '*.hst'
)

$results = @()

Show-Banner
    
try {
    Get-LoggedInUsers
    Get-NonDefaultFolders
    Get-NonDefaultPrograms
    Get-NonDefaultScheduledTasks
    Get-NonDefaultServices
    Get-RunningProcesses
    Get-PuttyCredentials

    # Get command history files
    $historyResults = Get-HistoryFiles
    
    # Export history files
    if ($historyResults.Count -gt 0) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $historyPath = "scout_history_${timestamp}.txt"
        
        foreach ($history in $historyResults) {
            Add-Content -Path $historyPath -Value "`n=== $($history.Shell) History - $($history.Path) ===`n"
            Add-Content -Path $historyPath -Value $history.Content
        }
        Write-Host "[+] Command histories exported to $historyPath" -ForegroundColor Green
    }

    # Search C drive excluding standard Windows paths
    Write-Host "[*] Searching for files..." -ForegroundColor Blue
    
    # Add specific search for .ssh directory
    Write-Host "[*] Checking for SSH directories..." -ForegroundColor Blue
    Get-ChildItem -Path "C:\Users\" -Directory | ForEach-Object {
        $sshPath = Join-Path $_.FullName ".ssh"
        if (Test-Path $sshPath) {
            Write-Host "[!] Found .ssh directory: $sshPath" -ForegroundColor Yellow
        }
    }

    $files = Get-ChildItem -Path "C:\" -Recurse -File -Include $interestingExtensions -ErrorAction SilentlyContinue | 
        Where-Object {
            $file = $_
            -not ($excludedPaths | Where-Object { $file.FullName -like "$_*" })
        }

    foreach ($file in $files) {
        # Get file creation and modification times
        $fileInfo = @{
            'Path' = $file.FullName
            'Size(KB)' = [math]::Round($file.Length/1KB, 2)
            'LastModified' = $file.LastWriteTime
            'Created' = $file.CreationTime
            'Extension' = $file.Extension
        }
        
        # Check if file is empty
        if ($file.Length -eq 0) {
            continue
        }
        
        # Get first few lines of text files to help identify interesting content
        if (@('.txt', '.log', '.conf', '.config', '.ini') -contains $file.Extension) {
            try {
                $preview = Get-Content -Path $file.FullName -TotalCount 3 -ErrorAction SilentlyContinue
                $fileInfo['Preview'] = ($preview -join ' ').Substring(0, [Math]::Min(100, ($preview -join ' ').Length))
            }
            catch {
                $fileInfo['Preview'] = "Unable to read file content"
            }
        }
        
        # Special handling for potential key files
        if ($file.Name -like "id_*" -or $file.Extension -in @(".key", ".pem", ".ppk", ".pub")) {
            Write-Host "[!] Potential private/public key found: $($file.FullName)" -ForegroundColor Yellow
        }
        
        $results += New-Object PSObject -Property $fileInfo
    }

    # Output results
    Write-Host "`n[+] Found $($results.Count) potentially interesting files" -ForegroundColor Green
    
    # Group results by extension
    $results | Group-Object Extension | ForEach-Object {
        Write-Host "`n[+] $($_.Name) files found: $($_.Count)" -ForegroundColor Yellow
        $_.Group | Select-Object Path, 'Size(KB)', LastModified | Format-Table -AutoSize
    }
    
    # Export detailed results to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvPath = "scout_results_${timestamp}.csv"
    $results | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "`n[+] Detailed results exported to $csvPath" -ForegroundColor Green

} catch {
    Write-Host "[!] Error occurred: $_" -ForegroundColor Red
}